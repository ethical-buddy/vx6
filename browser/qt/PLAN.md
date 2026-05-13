# VX6 Qt Browser Plan

This file explains what the browser frontend is, how it is built today, how to contribute to it, what still needs to be done, and how to test it on Linux, Windows, and macOS.

## What This Browser Is

The browser frontend is a Qt WebEngine application that sits on top of the VX6 Go core.

It is not the protocol itself.
It is not a second network stack.
It is a local user-facing shell that talks to the current `vx6` binary and presents VX6 features in a browser-like layout.

The core ideas are:

- one VX6 system key
- one VX6 user identity display name that can change
- one shared network backend
- one frontend layer for browsing, logs, and local control

## What Exists Right Now

The current browser app already provides:

- a colorful home page
- `vx6://` internal pages
- tabs
- address bar
- back / forward / reload / home
- bookmark action
- a left control drawer for:
  - copyable current IPv6
  - node rename
  - service / node / hidden lookup
  - service hosting and stop controls
  - file send with target address
  - receive mode toggle (enable/disable)
  - receive status page
- a side drawer for runtime logs
- a side drawer for node control
- a node start button
- a node stop button
- reload and status actions
- first-run permission guidance for Windows and macOS
- `vx6://files` page showing:
  - receive status (mode, allowed senders)
  - config path
  - download directory
  - received files grouped by sender folder (`sender_name_nodeID_vx6`)
- `vx6://transfers` page showing:
  - sender-grouped received transfers
  - browser-side sent transfer history
  - transfer timestamps and status
  - transfer dashboard navigation integration

## How It Is Built Today

The browser is in `browser/qt`.

Main pieces:

- `browser/qt/CMakeLists.txt`
  - CMake build entry for Qt 6 WebEngine
- `browser/qt/src/main.cpp`
  - starts the app and registers the `vx6://` custom scheme
- `browser/qt/src/browserwindow.cpp`
  - main window, toolbar, tabs, log drawer, and node control
- `browser/qt/src/vx6backend.cpp`
  - runs the VX6 binary and turns command output into pages
- `browser/qt/src/vx6schemehandler.cpp`
  - serves `vx6://` pages inside Qt WebEngine

The browser does not implement VX6 discovery or routing itself.
It calls the existing Go binary, so the protocol stays in one place.

## Browser Layout

The current UI direction is:

- strong visual contrast
- colorful cards
- large home dashboard
- quick access actions visible immediately
- side log panel instead of burying logs in menus
- no profile switching UI
- one system, one key, one main identity

Important feature areas:

- top bar: navigation and address entry
- center: VX6 home dashboard and tabs
- right side: logs, start/stop, reload, status, firewall guidance
- left side: control drawer with the main operator actions
- internal pages: status, DHT, registry, services, peers, identity, lookup pages

## What We Want Next

The browser is intentionally incomplete right now.

Planned follow-up work:

- better tab/session persistence
- nicer page transitions and a sliding right drawer animation
- a polished left drawer animation and inline status badges
- better inline error pages when VX6 lookup fails
- richer service pages for public, private, and hidden records
- a browser home page that can show local services and recent connections
- safer web permissions prompts
- better integrated localhost and internet navigation rules 
- file transfer progress indicators and download speed display
- a button to open received file folders directly on the filesystem
- browser-side visualization for sender-grouped received file folders
- automatic creation of sender-specific receive directories during incoming file transfers
- safer receive storage organization instead of mixing VX6 files into the global Downloads directory
- debugging and validation work for ensuring the active runtime receive path correctly creates sender-specific receive folders
- future transfer history and per-sender download tracking support
- safer receive storage organization outside the global Downloads root
- automatic sender-grouped receive directory creation during incoming transfers
- browser-side transfer history persistence for sent and received transfers
- transfer retry and failed-transfer recovery support
- transfer progress tracking and live speed monitoring integration
- runtime validation for active receive-directory creation behavior
- recent peer activity tracking and persistence
- transfer observability and operational logging improvements
- safer local file access and filesystem permission handling
- better localhost and internet navigation separation enforcement
- session persistence for active VX6 tabs and internal pages
- future queued/offline transfer experimentation for decentralized delivery workflows

## How To Contribute

The safest contribution model is:

1. keep VX6 protocol changes in the Go core only
2. keep browser work inside `browser/qt`
3. keep Qt UI changes separate from protocol changes
4. update docs whenever a visible browser behavior changes
5. test the browser shell on at least Linux before claiming a UI change is done

Good browser contributions are usually one of these:

- a new VX6 page
- a layout improvement
- a node control improvement
- file transfer UI or download status support
- a safer browser permission rule
- a better cross-platform build fix
- a clearer error page

Avoid mixing browser UI work with DHT or hidden-service logic unless the change really touches both.

## Build Steps

Linux example:

```bash
cmake -S browser/qt -B browser/qt/build -DCMAKE_BUILD_TYPE=Release
cmake --build browser/qt/build
```

If Qt is not found automatically, point CMake at your Qt installation first.

Windows example:

```powershell
cmake -S browser/qt -B browser/qt/build -DCMAKE_BUILD_TYPE=Release
cmake --build browser/qt/build --config Release
```

macOS example:

```bash
cmake -S browser/qt -B browser/qt/build -DCMAKE_BUILD_TYPE=Release
cmake --build browser/qt/build
```

The browser expects the VX6 binary to be available as:

- a direct `--vx6-bin` path
- or a `vx6` binary beside the browser executable
- or a `vx6` binary available in `PATH`

## Testing Plan

### Linux

Test on a real Linux desktop first.

Checks:

- browser compiles
- browser opens
- `vx6://home` loads
- `vx6://status` loads
- `vx6://dht` loads
- side log drawer works
- node start/stop works
- reload works
- bookmarks work

### Windows

Test on a real Windows 11 or Windows Server machine.

Checks:

- browser compiles with the Windows Qt toolchain
- browser opens without path problems
- `vx6.exe` is found or passed explicitly
- first-run permission prompt appears when needed
- firewall/admin guidance is visible
- node start/stop works
- local browser pages load

### macOS

Test on a real macOS machine.

Checks:

- browser compiles with the macOS Qt toolchain
- browser opens normally
- first-run network permission guidance appears
- node start/stop works
- local browser pages load
- status and DHT pages render correctly

### BSD

BSD is a later support track.

Only treat BSD as ready when the browser build and runtime are verified on a real BSD host.

## UI Rules

The browser should stay:

- easy to read
- colorful but not noisy
- fast to navigate
- obvious about what is local VX6 content and what is normal web content
- safe by default

UI style rules:

- use large cards for common VX6 actions
- keep the address bar visible
- keep the runtime log drawer accessible
- use readable colors with clear contrast
- keep the browser home page useful without hiding everything behind menus

## Security Rules

The browser must not weaken the VX6 core.

That means:

- browser UI must not replace protocol validation
- `vx6://` pages must stay local and controlled
- file URLs should stay restricted by default
- unsafe script and navigation behavior should stay limited
- Windows and macOS permissions should be requested clearly

## Short Version

The browser is a Qt WebEngine frontend over VX6.

Today it already has:

- a local home page
- `vx6://` pages
- logs
- reload
- status
- node start/stop

Next we want:

- better layout polish
- stronger cross-platform packaging
- better local browser behavior
- more polished service pages
