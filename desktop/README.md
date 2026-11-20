# LSADRA desktop

A lightweight tray app for running LSADRA on one computer. It is built with
[Tauri v2](https://v2.tauri.app/) around the existing React dashboard in
`frontend/`, so the installer is about 2 MB and uses the system webview
instead of shipping a browser.

What it does:

- Starts the LSADRA server on `127.0.0.1` (never on the network) and stops it
  when you quit. If a server is already answering on the port, it uses that
  one and leaves it running.
- Shows the dashboard in a native window. Closing the window keeps LSADRA in
  the tray; left-click the tray icon to bring it back.
- Tray menu: server status, **Open dashboard**, **Start/Stop server**, the
  server log path, **Quit LSADRA**.
- Creates a random JWT signing secret on first run and keeps it in the app
  data folder (owner-only on Linux and macOS), so sessions survive restarts
  without dev mode or a placeholder secret. An `LSADRA_JWT_SECRET` already in
  the environment wins and is never written to disk.
- Adds the window's own origins (`tauri://localhost`, `http(s)://tauri.localhost`)
  to the server's CORS allowlist, keeping any origins you set.

The dashboard window gets no Tauri commands (`capabilities` is empty), and its
Content-Security-Policy only allows connections to the local API, so a page
in the window cannot reach the filesystem, the shell or other hosts.

## Install the server

The app runs an installed `lsadra-server`, so it needs no source checkout.
Install the server once, with Python 3.12 or newer, from a release or a
checkout:

```bash
pipx install /path/to/lsadra        # or: pip install /path/to/lsadra
```

pipx puts `lsadra-server` and `lsadra-admin` in `~/.local/bin` (Linux and
macOS) or `%USERPROFILE%\.local\bin` (Windows), which the app checks even
when it is started from a desktop menu with a short `PATH`. A self-contained
server bundled into the installer, so no Python is needed, is planned.

### Where the data goes

An installed server keeps its database, models, TLS files and runtime intel in
this user's app data folder, in a `server` subfolder, and its logs in the app
log folder. The app sets `LSADRA_DATA_DIR` and `LSADRA_LOG_DIR` for it and
starts it from the data folder, so nothing is written where the app was
launched. Set either variable yourself to choose another folder. The tray menu
shows the data folder in use.

| OS      | Data (`LSADRA_DATA_DIR`)                                          | Logs                                           |
|---------|-------------------------------------------------------------------|------------------------------------------------|
| Linux   | `~/.local/share/io.github.tsmanral.lsadra/server`                 | `~/.local/share/io.github.tsmanral.lsadra/logs` |
| Windows | `%APPDATA%\io.github.tsmanral.lsadra\server`                      | `%LOCALAPPDATA%\io.github.tsmanral.lsadra\logs` |
| macOS   | `~/Library/Application Support/io.github.tsmanral.lsadra/server` | `~/Library/Logs/io.github.tsmanral.lsadra`     |

A server run from a source checkout keeps the checkout's own `data/` and
`logs/`, as it does when started by hand.

## Run it from a checkout

Set up the Python side first (Quick Start step 1 in the main README), then:

```bash
cd frontend && npm ci && npm run build && cd ..
cd desktop
npm ci
npm run dev        # development window with hot reload of the dashboard
npm run build      # release build and installers in src-tauri/target/release/bundle/
```

Linux needs the webview and tray libraries:
`sudo apt install libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev`.
Windows and macOS need nothing extra beyond Rust and Node.

## First account

Self sign-up is off outside dev mode, so create the first admin before logging
in. Point `lsadra-admin` at the same data folder the app uses (dev mode is fine
for this one command; it only writes the account to that database):

```bash
# Installed server (Linux path shown; see the table above for yours)
LSADRA_DEV_MODE=true LSADRA_DATA_DIR=~/.local/share/io.github.tsmanral.lsadra/server \
  lsadra-admin create-admin --username you

# Source checkout
LSADRA_DEV_MODE=true python -m lsadra.admin_cli create-admin --username you
```

A first-run setup screen inside the app is planned.

## How it finds the server

In order:

1. A self-contained `lsadra-server` (`lsadra-server.exe` on Windows) next to
   the app executable (planned bundled build).
2. The `server` setting or `LSADRA_SERVER`: the path of an installed
   `lsadra-server`.
3. The `server_dir` setting or `LSADRA_HOME`: a source checkout.
4. A checkout found by walking up from the app executable, so `npm run dev`
   in `desktop/` works with no settings.
5. `lsadra-server` on `PATH`, then in `~/.local/bin`.

In a checkout it runs `python -m lsadra.serve` when that module exists
(it applies the listener and TLS policy), otherwise
`python -m uvicorn server:app --host 127.0.0.1 --port <port>`. The Python used is
`python` from settings or `LSADRA_PYTHON`, else the checkout's `.venv`, else
`python3` (`python` on Windows).

## Settings

`settings.json` in the app config folder (Linux `~/.config/io.github.tsmanral.lsadra/`,
Windows `%APPDATA%\io.github.tsmanral.lsadra\`, macOS
`~/Library/Application Support/io.github.tsmanral.lsadra/`). It is created
empty on first run. Environment variables override it.

| Field        | Environment       | Default                 |
|--------------|-------------------|-------------------------|
| `server`     | `LSADRA_SERVER`   | `lsadra-server` on `PATH` |
| `server_dir` | `LSADRA_HOME`     | found as described above |
| `python`     | `LSADRA_PYTHON`   | `.venv`, then system Python |
| `port`       | `LSADRA_API_PORT` | `8000`                  |
| `autostart`  |                   | `true`                  |

The dashboard currently calls the API at `http://localhost:8000`, so keep the
port at 8000 until the dashboard reads its API address at run time.

The server log is `server.log` in the app log folder; the tray menu shows
its path. It starts over after 5 MB.

## Tests

```bash
cd desktop/src-tauri
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

CI runs these on Linux, Windows and macOS (`.github/workflows/desktop.yml`) and
builds unsigned installers on pushes to `main`.
