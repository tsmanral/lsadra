//! LSADRA desktop: a tray app that runs the local LSADRA server and shows the
//! React dashboard in a native window.
//!
//! The window loads the dashboard bundled into the app and talks to the server
//! on 127.0.0.1 over its normal REST and WebSocket API. The webview gets no
//! Tauri commands (`capabilities` is empty), so a page in the window cannot
//! reach the filesystem, the shell or the server process.

pub mod server;
pub mod settings;

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, RunEvent, WindowEvent};

use server::{data_dir_of, data_env, find_installed, resolve_launch, server_env, Server, Status};
use settings::Settings;

const MAIN_WINDOW: &str = "main";

fn show_dashboard(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn toggle_label(status: &Status) -> &'static str {
    if status.is_running() {
        "Stop server"
    } else {
        "Start server"
    }
}

/// SIGTERM (logout, shutdown), SIGINT (Ctrl-C in `npm run dev`) and SIGHUP
/// exit the app the normal way, so the server it started is stopped too.
#[cfg(unix)]
fn stop_on_signals(app: AppHandle) -> std::io::Result<()> {
    use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
    let mut signals = signal_hook::iterator::Signals::new([SIGTERM, SIGINT, SIGHUP])?;
    thread::spawn(move || {
        if signals.forever().next().is_some() {
            app.state::<Arc<Server>>().stop();
            app.exit(0);
        }
    });
    Ok(())
}

pub fn run() {
    let app = tauri::Builder::default()
        .setup(|app| {
            let handle = app.handle().clone();
            let paths = app.path();
            let config_dir = paths.app_config_dir()?;
            let data_dir = paths.app_data_dir()?;
            let log_dir = paths.app_log_dir()?;

            let settings =
                Settings::resolve(settings::load_file(&config_dir), |k| std::env::var(k).ok());
            let exe_dir = std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.to_path_buf()));
            let installed = find_installed(std::env::var_os("PATH"), paths.home_dir().ok());
            let launch = resolve_launch(&settings, exe_dir.as_deref(), installed);
            let secret = settings::jwt_secret(&data_dir)?;
            let mut env = server_env(settings.port, &secret, |k| std::env::var(k).ok());
            // A packaged server keeps its database and models in this user's
            // app data folder, apart from the desktop app's own files.
            env.extend(data_env(&launch, &data_dir.join("server"), &log_dir, |k| {
                std::env::var(k).ok()
            }));
            let data_text = match data_dir_of(&env, |k| std::env::var(k).ok()) {
                Some(dir) => format!("Data: {}", dir.display()),
                None => "Data: the checkout's data folder".to_string(),
            };
            let server = Arc::new(Server::new(
                launch,
                settings.port,
                env,
                log_dir.join("server.log"),
            ));
            app.manage(server.clone());

            if settings.autostart {
                if let Err(err) = server.start() {
                    eprintln!("lsadra-desktop: {err}");
                }
            }

            let status_item =
                MenuItem::with_id(app, "status", Status::Stopped.label(), false, None::<&str>)?;
            let open_item = MenuItem::with_id(app, "open", "Open dashboard", true, None::<&str>)?;
            let toggle_item = MenuItem::with_id(app, "toggle", "Start server", true, None::<&str>)?;
            let log_text = format!("Server log: {}", server.log_path().display());
            let log_item = MenuItem::with_id(app, "log", log_text, false, None::<&str>)?;
            let data_item = MenuItem::with_id(app, "data", data_text, false, None::<&str>)?;
            let quit_item = MenuItem::with_id(app, "quit", "Quit LSADRA", true, None::<&str>)?;
            let menu = Menu::with_items(
                app,
                &[
                    &status_item,
                    &open_item,
                    &toggle_item,
                    &PredefinedMenuItem::separator(app)?,
                    &data_item,
                    &log_item,
                    &PredefinedMenuItem::separator(app)?,
                    &quit_item,
                ],
            )?;

            let mut tray = TrayIconBuilder::with_id("lsadra")
                .tooltip("LSADRA")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| {
                    let server = app.state::<Arc<Server>>();
                    match event.id().as_ref() {
                        "open" => show_dashboard(app),
                        "toggle" => {
                            if server.status().is_running() {
                                server.stop();
                            } else if let Err(err) = server.start() {
                                eprintln!("lsadra-desktop: {err}");
                            }
                        }
                        "quit" => {
                            server.stop();
                            app.exit(0);
                        }
                        _ => {}
                    }
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        show_dashboard(tray.app_handle());
                    }
                });
            if let Some(icon) = app.default_window_icon() {
                tray = tray.icon(icon.clone());
            }
            tray.build(app)?;

            #[cfg(unix)]
            stop_on_signals(app.handle().clone())?;

            // Keep the tray's status line and Start/Stop item current.
            thread::spawn(move || {
                let mut last: Option<Status> = None;
                loop {
                    let status = handle.state::<Arc<Server>>().status();
                    if last.as_ref() != Some(&status) {
                        let _ = status_item.set_text(status.label());
                        let _ = toggle_item.set_text(toggle_label(&status));
                        let _ = toggle_item.set_enabled(!matches!(
                            status,
                            Status::NotConfigured | Status::Running { owned: false }
                        ));
                        last = Some(status);
                    }
                    thread::sleep(Duration::from_secs(2));
                }
            });
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the window keeps LSADRA running in the tray.
            if let WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == MAIN_WINDOW {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .build(tauri::generate_context!())
        .expect("failed to build the LSADRA desktop app");

    app.run(|app, event| {
        if let RunEvent::Exit = event {
            if let Some(server) = app.try_state::<Arc<Server>>() {
                server.stop();
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toggle_follows_status() {
        assert_eq!(
            toggle_label(&Status::Running { owned: true }),
            "Stop server"
        );
        assert_eq!(toggle_label(&Status::Starting), "Stop server");
        assert_eq!(toggle_label(&Status::Stopped), "Start server");
        assert_eq!(toggle_label(&Status::Exited("x".into())), "Start server");
    }

    #[test]
    fn webview_gets_no_capabilities() {
        let conf: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        let caps = &conf["app"]["security"]["capabilities"];
        assert_eq!(
            caps,
            &serde_json::json!([]),
            "the dashboard window must not get Tauri commands"
        );
        assert_eq!(conf["app"]["withGlobalTauri"], serde_json::json!(false));
        let connect = conf["app"]["security"]["csp"]["connect-src"]
            .as_str()
            .unwrap();
        for host in connect
            .split_whitespace()
            .filter(|s| s.starts_with("http") || s.starts_with("ws"))
        {
            assert!(
                host.contains("://localhost")
                    || host.contains("://127.0.0.1")
                    || host == "http://ipc.localhost",
                "CSP lets the window connect off-machine: {host}"
            );
        }
    }
}
