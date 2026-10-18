# Optional products

The core VX6 node and SDK are maintained at the repository root. This directory groups optional user interfaces and application experiments. These are not built by the root `make build` target.

| Project | Source | State | Build |
|---|---|---|---|
| VX6 GUI | `cmd/vx6-gui` | Local web UI wrapping the `vx6` executable | `go build -o vx6-gui ./cmd/vx6-gui` from repository root |
| Qt browser | `products/browser/qt` | Separate Qt WebEngine frontend | See `products/browser/qt/README.md`; CMake build |
| Comms desktop | `products/apps/vx6comms` | Go/Fyne app using the SDK | See its README; `go build -o vx6comms ./products/apps/vx6comms` |
| Comms Tauri | `products/apps/vx6comms-tauri` | Active UI work; check README and plan | Tauri/npm build in that directory |
| Comms Android | `products/apps/vx6comms-android` | Planning/scaffold documentation; no application source currently tracked | Start from its README and plan |
| Shared backend | `products/apps/vx6backend` | Separate backend API experiment | `go build -o vx6d ./products/apps/vx6backend/cmd/vx6d` |
| VX6Share | `products/apps/vx6share` | Go file-sharing app using the SDK | `go build -o vx6share ./products/apps/vx6share` |
| Mobile bridge | `products/mobile` | gomobile bridge over the SDK; platform apps are not present here | See `products/mobile/README.md` |

Root `make build` creates only `vx6`. These optional products remain in the same Go module for now; moving them into independent repositories requires coordinating their remotes and release ownership.
