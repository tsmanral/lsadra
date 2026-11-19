//! `EvtSubscribe` pull loop with a persisted bookmark (Windows only).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::ptr;

use lsadra_collector_core::Event;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS, ERROR_TIMEOUT, HANDLE,
};
use windows_sys::Win32::System::EventLog::{
    EvtClose, EvtCreateBookmark, EvtNext, EvtRender, EvtRenderBookmark, EvtRenderEventXml, EvtSubscribe,
    EvtSubscribeStartAfterBookmark, EvtSubscribeToFutureEvents, EvtUpdateBookmark, EVT_HANDLE,
};
use windows_sys::Win32::System::Threading::{CreateEventW, ResetEvent, WaitForSingleObject};

use crate::map_event_xml;

const BOOKMARK_FILE: &str = "wineventlog.bookmark.xml";
const BATCH: usize = 32;

struct Evt(EVT_HANDLE);

impl Drop for Evt {
    fn drop(&mut self) {
        if self.0 != 0 {
            // SAFETY: the handle came from an Evt* call and is closed once.
            unsafe { EvtClose(self.0) };
        }
    }
}

struct Signal(HANDLE);

impl Drop for Signal {
    fn drop(&mut self) {
        // SAFETY: the handle came from CreateEventW and is closed once.
        unsafe { CloseHandle(self.0) };
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn last_error(what: &str) -> io::Error {
    // SAFETY: GetLastError has no preconditions.
    let code = unsafe { GetLastError() };
    io::Error::other(format!("{what} failed (Windows error {code})"))
}

/// Render an event or bookmark handle to a UTF-8 string.
fn render(handle: EVT_HANDLE, flags: u32) -> io::Result<String> {
    let mut used = 0u32;
    let mut props = 0u32;
    // SAFETY: a zero-size probe call; Windows reports the size it needs.
    let ok = unsafe { EvtRender(0, handle, flags, 0, ptr::null_mut(), &mut used, &mut props) };
    if ok == 0 {
        // SAFETY: GetLastError has no preconditions.
        if unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
            return Err(last_error("EvtRender"));
        }
    }
    let mut buf = vec![0u16; (used as usize).div_ceil(2)];
    let size = (buf.len() * 2) as u32;
    // SAFETY: buf holds `size` bytes, as EvtRender asked for.
    let ok = unsafe {
        EvtRender(
            0,
            handle,
            flags,
            size,
            buf.as_mut_ptr().cast(),
            &mut used,
            &mut props,
        )
    };
    if ok == 0 {
        return Err(last_error("EvtRender"));
    }
    let chars = (used as usize / 2).min(buf.len());
    let end = buf[..chars].iter().position(|&c| c == 0).unwrap_or(chars);
    Ok(String::from_utf16_lossy(&buf[..end]))
}

pub struct WinEventLogSource {
    query: String,
    bookmark_path: PathBuf,
}

impl WinEventLogSource {
    pub fn new(query: Option<String>, state_dir: &Path) -> Self {
        WinEventLogSource {
            query: query.unwrap_or_else(crate::default_query),
            bookmark_path: state_dir.join(BOOKMARK_FILE),
        }
    }

    fn save_bookmark(&self, bookmark: EVT_HANDLE) -> io::Result<()> {
        let xml = render(bookmark, EvtRenderBookmark)?;
        let tmp = self.bookmark_path.with_extension("tmp");
        fs::write(&tmp, xml)?;
        fs::rename(&tmp, &self.bookmark_path)
    }

    /// Run until an error; `sink` spools each event.
    pub fn run(&self, sink: &mut dyn FnMut(Event) -> io::Result<()>) -> io::Result<()> {
        let saved = fs::read_to_string(&self.bookmark_path)
            .ok()
            .filter(|s| s.contains("<BookmarkList"));
        let bookmark = match &saved {
            // SAFETY: a NUL-terminated UTF-16 string that outlives the call.
            Some(xml) => Evt(unsafe { EvtCreateBookmark(wide(xml).as_ptr()) }),
            // SAFETY: a null bookmark XML creates an empty bookmark.
            None => Evt(unsafe { EvtCreateBookmark(ptr::null()) }),
        };
        if bookmark.0 == 0 {
            return Err(last_error("EvtCreateBookmark"));
        }

        // SAFETY: manual-reset event, initially signalled, unnamed.
        let signal = Signal(unsafe { CreateEventW(ptr::null(), 1, 1, ptr::null()) });
        if signal.0.is_null() {
            return Err(last_error("CreateEventW"));
        }

        let flags = if saved.is_some() {
            EvtSubscribeStartAfterBookmark
        } else {
            EvtSubscribeToFutureEvents
        };
        let query = wide(&self.query);
        // SAFETY: all pointers are valid for the call; no callback (pull model).
        let sub = Evt(unsafe {
            EvtSubscribe(
                0,
                signal.0,
                ptr::null(),
                query.as_ptr(),
                if saved.is_some() { bookmark.0 } else { 0 },
                ptr::null(),
                None,
                flags,
            )
        });
        if sub.0 == 0 {
            return Err(last_error(
                "EvtSubscribe (run the agent as an administrator or LocalSystem)",
            ));
        }

        loop {
            // SAFETY: signal is a live event handle.
            unsafe { WaitForSingleObject(signal.0, 1000) };
            loop {
                let mut handles = [0isize; BATCH];
                let mut returned = 0u32;
                // SAFETY: `handles` has room for BATCH handles.
                let ok = unsafe { EvtNext(sub.0, BATCH as u32, handles.as_mut_ptr(), 0, 0, &mut returned) };
                if ok == 0 {
                    // SAFETY: GetLastError has no preconditions.
                    let code = unsafe { GetLastError() };
                    if code == ERROR_NO_MORE_ITEMS || code == ERROR_TIMEOUT {
                        // SAFETY: signal is a live event handle.
                        unsafe { ResetEvent(signal.0) };
                        break;
                    }
                    return Err(last_error("EvtNext"));
                }
                let events: Vec<Evt> = handles[..returned as usize].iter().map(|&h| Evt(h)).collect();
                for ev in &events {
                    match render(ev.0, EvtRenderEventXml) {
                        Ok(xml) => {
                            if let Some(e) = map_event_xml(&xml) {
                                sink(e)?;
                            }
                        }
                        Err(e) => {
                            eprintln!("lsadra-agent: skipping an event that failed to render: {e}")
                        }
                    }
                    // SAFETY: both handles are live.
                    if unsafe { EvtUpdateBookmark(bookmark.0, ev.0) } == 0 {
                        return Err(last_error("EvtUpdateBookmark"));
                    }
                }
                self.save_bookmark(bookmark.0)?;
            }
        }
    }
}
