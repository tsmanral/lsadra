//! Size-capped on-disk spool with an acknowledged read offset.
//!
//! Events are appended as one compact JSON object per line to numbered
//! segment files (`00000000000000000001.seg`, …). The shipper reads from the
//! acked position, and only after the core answers does it move the ack
//! forward; the ack lives in `ack` and is replaced atomically (write + rename).
//! So a crash or kill at any point loses no event that was appended, and at
//! worst re-sends the batch that was in flight.
//!
//! Appends are plain `write` calls, which survive the process being killed;
//! segments are `fsync`ed when they are closed. A power cut can lose the tail
//! of the open segment, which is the usual trade for a log agent.
//!
//! When the spool is over its byte cap (the core has been unreachable for a
//! long time), whole segments are dropped oldest first and counted, so the
//! agent's disk use stays bounded.

use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const SEG_SUFFIX: &str = ".seg";
const ACK_FILE: &str = "ack";

/// A read position: segment id and byte offset inside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Position {
    pub segment: u64,
    pub offset: u64,
}

/// Lines read from the spool and the position just after the last one.
#[derive(Debug, Default)]
pub struct Batch {
    pub lines: Vec<String>,
    pub next: Option<Position>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SpoolStats {
    pub pending_bytes: u64,
    pub segments: usize,
    pub dropped_segments: u64,
    pub dropped_bytes: u64,
}

struct Inner {
    /// (id, length in bytes), oldest first; the last one is open for writing.
    segments: VecDeque<(u64, u64)>,
    writer: File,
    ack: Position,
    dropped_segments: u64,
    dropped_bytes: u64,
}

pub struct Spool {
    dir: PathBuf,
    max_bytes: u64,
    segment_bytes: u64,
    inner: Mutex<Inner>,
}

fn seg_path(dir: &Path, id: u64) -> PathBuf {
    dir.join(format!("{id:020}{SEG_SUFFIX}"))
}

fn read_ack(dir: &Path) -> Option<Position> {
    let text = fs::read_to_string(dir.join(ACK_FILE)).ok()?;
    let mut parts = text.split_whitespace();
    let segment = parts.next()?.parse().ok()?;
    let offset = parts.next()?.parse().ok()?;
    Some(Position { segment, offset })
}

fn write_ack(dir: &Path, pos: Position) -> io::Result<()> {
    let tmp = dir.join(format!("{ACK_FILE}.tmp"));
    {
        let mut f = File::create(&tmp)?;
        writeln!(f, "{} {}", pos.segment, pos.offset)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, dir.join(ACK_FILE))
}

/// Cut a torn final line (a write the process did not finish before it died).
fn truncate_torn_tail(path: &Path) -> io::Result<u64> {
    let mut f = OpenOptions::new().read(true).write(true).open(path)?;
    let len = f.metadata()?.len();
    if len == 0 {
        return Ok(0);
    }
    // Scan back for the last newline in chunks.
    let mut end = len;
    let mut buf = vec![0u8; 8192];
    loop {
        let start = end.saturating_sub(buf.len() as u64);
        let n = (end - start) as usize;
        f.seek(SeekFrom::Start(start))?;
        f.read_exact(&mut buf[..n])?;
        if let Some(i) = buf[..n].iter().rposition(|&b| b == b'\n') {
            let keep = start + i as u64 + 1;
            if keep != len {
                f.set_len(keep)?;
                f.sync_all()?;
            }
            return Ok(keep);
        }
        if start == 0 {
            f.set_len(0)?;
            f.sync_all()?;
            return Ok(0);
        }
        end = start;
    }
}

impl Spool {
    /// Open (or create) the spool in `dir`. `max_bytes` caps the whole spool;
    /// `segment_bytes` is the size at which a new segment is started.
    pub fn open(dir: impl Into<PathBuf>, max_bytes: u64, segment_bytes: u64) -> io::Result<Spool> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        let segment_bytes = segment_bytes.max(4096);
        let max_bytes = max_bytes.max(segment_bytes * 2);

        let mut ids: Vec<u64> = fs::read_dir(&dir)?
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let name = e.file_name().into_string().ok()?;
                name.strip_suffix(SEG_SUFFIX)?.parse::<u64>().ok()
            })
            .collect();
        ids.sort_unstable();

        let mut segments = VecDeque::new();
        for (i, id) in ids.iter().enumerate() {
            let path = seg_path(&dir, *id);
            let len = if i + 1 == ids.len() {
                truncate_torn_tail(&path)?
            } else {
                fs::metadata(&path)?.len()
            };
            segments.push_back((*id, len));
        }
        if segments.is_empty() {
            segments.push_back((1, 0));
        }
        let (last_id, _) = *segments.back().expect("non-empty");
        let writer = OpenOptions::new()
            .create(true)
            .append(true)
            .open(seg_path(&dir, last_id))?;

        let first = segments.front().expect("non-empty").0;
        let mut ack = read_ack(&dir).unwrap_or(Position {
            segment: first,
            offset: 0,
        });
        if ack.segment < first {
            ack = Position {
                segment: first,
                offset: 0,
            };
        }
        if let Some(&(_, len)) = segments.iter().find(|(id, _)| *id == ack.segment) {
            ack.offset = ack.offset.min(len);
        }

        Ok(Spool {
            dir,
            max_bytes,
            segment_bytes,
            inner: Mutex::new(Inner {
                segments,
                writer,
                ack,
                dropped_segments: 0,
                dropped_bytes: 0,
            }),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Append one record. `line` must not contain a newline (compact JSON never does).
    pub fn append(&self, line: &str) -> io::Result<()> {
        if line.contains('\n') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "record contains a newline",
            ));
        }
        let mut inner = self.lock();
        let record_len = line.len() as u64 + 1;
        let (cur_id, cur_len) = *inner.segments.back().expect("non-empty");
        if cur_len > 0 && cur_len + record_len > self.segment_bytes {
            inner.writer.sync_all()?;
            let next = cur_id + 1;
            inner.writer = OpenOptions::new()
                .create(true)
                .append(true)
                .open(seg_path(&self.dir, next))?;
            inner.segments.push_back((next, 0));
        }
        let mut buf = Vec::with_capacity(record_len as usize);
        buf.extend_from_slice(line.as_bytes());
        buf.push(b'\n');
        inner.writer.write_all(&buf)?;
        inner.segments.back_mut().expect("non-empty").1 += record_len;
        self.enforce_cap(&mut inner)
    }

    fn enforce_cap(&self, inner: &mut Inner) -> io::Result<()> {
        loop {
            let total: u64 = inner.segments.iter().map(|(_, l)| l).sum();
            if total <= self.max_bytes || inner.segments.len() < 2 {
                return Ok(());
            }
            let (id, len) = inner.segments.pop_front().expect("len >= 2");
            fs::remove_file(seg_path(&self.dir, id)).or_else(ignore_missing)?;
            let unread = if inner.ack.segment == id {
                len - inner.ack.offset
            } else if inner.ack.segment > id {
                0
            } else {
                len
            };
            inner.dropped_segments += 1;
            inner.dropped_bytes += unread;
            if inner.ack.segment <= id {
                inner.ack = Position {
                    segment: inner.segments.front().expect("non-empty").0,
                    offset: 0,
                };
                write_ack(&self.dir, inner.ack)?;
            }
        }
    }

    /// Read up to `max` records from the acked position without consuming them.
    pub fn peek(&self, max: usize) -> io::Result<Batch> {
        let inner = self.lock();
        let mut out = Batch::default();
        let mut pos = inner.ack;
        for &(id, len) in inner.segments.iter().filter(|(id, _)| *id >= inner.ack.segment) {
            if out.lines.len() >= max {
                break;
            }
            if id != pos.segment {
                pos = Position {
                    segment: id,
                    offset: 0,
                };
            }
            if pos.offset >= len {
                continue;
            }
            let mut f = File::open(seg_path(&self.dir, id))?;
            f.seek(SeekFrom::Start(pos.offset))?;
            let mut reader = BufReader::new(f.take(len - pos.offset));
            let mut line = String::new();
            while out.lines.len() < max {
                line.clear();
                let n = reader.read_line(&mut line)?;
                if n == 0 || !line.ends_with('\n') {
                    break;
                }
                pos.offset += n as u64;
                out.lines.push(line.trim_end_matches('\n').to_string());
                out.next = Some(pos);
            }
        }
        Ok(out)
    }

    /// Mark everything before `pos` as delivered and delete finished segments.
    pub fn ack(&self, pos: Position) -> io::Result<()> {
        let mut inner = self.lock();
        if pos <= inner.ack {
            return Ok(()); // stale (the cap already moved past it)
        }
        write_ack(&self.dir, pos)?;
        inner.ack = pos;
        let current = inner.segments.back().expect("non-empty").0;
        while let Some(&(id, len)) = inner.segments.front() {
            let finished = id < pos.segment || (id == pos.segment && pos.offset >= len && id != current);
            if !finished || id == current {
                break;
            }
            inner.segments.pop_front();
            fs::remove_file(seg_path(&self.dir, id)).or_else(ignore_missing)?;
        }
        Ok(())
    }

    pub fn stats(&self) -> SpoolStats {
        let inner = self.lock();
        let pending = inner
            .segments
            .iter()
            .map(|&(id, len)| match id.cmp(&inner.ack.segment) {
                std::cmp::Ordering::Less => 0,
                std::cmp::Ordering::Equal => len.saturating_sub(inner.ack.offset),
                std::cmp::Ordering::Greater => len,
            })
            .sum();
        SpoolStats {
            pending_bytes: pending,
            segments: inner.segments.len(),
            dropped_segments: inner.dropped_segments,
            dropped_bytes: inner.dropped_bytes,
        }
    }
}

fn ignore_missing(e: io::Error) -> io::Result<()> {
    if e.kind() == io::ErrorKind::NotFound {
        Ok(())
    } else {
        Err(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(i: usize) -> String {
        format!("{{\"n\":{i},\"pad\":\"{}\"}}", "x".repeat(40))
    }

    #[test]
    fn append_peek_ack_and_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::open(dir.path(), 1 << 20, 4096).unwrap();
        for i in 0..200 {
            spool.append(&rec(i)).unwrap();
        }
        assert!(spool.stats().segments > 1, "rotated");

        let b = spool.peek(100).unwrap();
        assert_eq!(b.lines.len(), 100);
        assert_eq!(b.lines[0], rec(0));
        spool.ack(b.next.unwrap()).unwrap();

        // Unacked records survive a restart; acked ones are not re-read.
        drop(spool);
        let spool = Spool::open(dir.path(), 1 << 20, 4096).unwrap();
        let b = spool.peek(1000).unwrap();
        assert_eq!(b.lines.len(), 100);
        assert_eq!(b.lines[0], rec(100));
        spool.ack(b.next.unwrap()).unwrap();
        assert_eq!(spool.stats().pending_bytes, 0);
        assert_eq!(spool.stats().segments, 1, "finished segments deleted");
        assert!(spool.peek(10).unwrap().lines.is_empty());
    }

    #[test]
    fn torn_tail_is_cut_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::open(dir.path(), 1 << 20, 1 << 16).unwrap();
        spool.append(&rec(1)).unwrap();
        drop(spool);
        let mut f = OpenOptions::new()
            .append(true)
            .open(seg_path(dir.path(), 1))
            .unwrap();
        f.write_all(b"{\"n\":2,\"pa").unwrap();
        drop(f);

        let spool = Spool::open(dir.path(), 1 << 20, 1 << 16).unwrap();
        spool.append(&rec(3)).unwrap();
        let b = spool.peek(10).unwrap();
        assert_eq!(b.lines, vec![rec(1), rec(3)]);
    }

    #[test]
    fn cap_drops_oldest_segments() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::open(dir.path(), 16384, 4096).unwrap();
        for i in 0..2000 {
            spool.append(&rec(i)).unwrap();
        }
        let s = spool.stats();
        assert!(s.pending_bytes <= 16384, "{s:?}");
        assert!(s.dropped_segments > 0 && s.dropped_bytes > 0);
        let b = spool.peek(1).unwrap();
        assert_ne!(b.lines[0], rec(0), "oldest were dropped");
        let last = spool.peek(10_000).unwrap();
        assert_eq!(last.lines.last().unwrap(), &rec(1999), "newest kept");
    }

    #[test]
    fn newline_in_record_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::open(dir.path(), 1 << 20, 4096).unwrap();
        assert!(spool.append("a\nb").is_err());
    }
}
