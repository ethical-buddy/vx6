# VX6 Open Issues

This file is a short task list for follow-up PRs.

## Protocol
- DHT store admission is now conservative, with authoritative publisher checks for trusted records. Operator-configurable publish tokens and closer-to-key admission could still strengthen high-trust deployments.
- DHT ASN diversity now works with offline maps, but we still need better operator tooling to generate and refresh those maps.
- Hidden-service lookup still has timing and volume leakage. Add more cover traffic and more regular polling.
- Hidden failover is improved, but an active stream still does not migrate perfectly when a relay dies. Add stronger reconnect and session handoff.
- DHT cache and stored records are still mostly memory-backed. Add bounded disk-backed storage for scale.
- Lookup and replication knobs are still only lightly tuned. Run churn and WAN tests for `alpha`, `beta`, replica count, and refresh intervals.

## Tor-Grade Security
- Add stronger traffic shaping for hidden services.
- Add better guard relay selection rules so path overlap is lower.
- Add more anti-Sybil checks for DHT writers and hidden-service relays.
- Add adversarial tests for alias guessing, timing observation, and relay correlation.
- Add a clearer threat model that states what VX6 protects and what it does not protect.

## Cross-Platform Support
- Keep the shared protocol code identical across Linux, Windows, macOS, and BSD.
- Add OS-specific adapter files only for paths, signals, firewall, and service manager behavior.
- Add macOS support files for launch/startup and firewall guidance.
- Add BSD support files for service startup and firewall guidance.
- Add a fuller browser product on top of `products/browser/qt` that talks to the same local VX6 runtime API on every OS.

## Windows
- Add a proper Windows installer that can create firewall rules during install.
- Add Authenticode signing for `vx6.exe`, `vx6-gui.exe`, and `vx6-browser.exe`.
- Add Windows service support so VX6 can run in the background cleanly.
- Add better Windows path handling for AppData, ProgramData, and service logs.
- Add live Windows integration tests on a real Windows host.
- Add a `vx6 doctor` command that reports firewall, advertise address, and peer sync health.

## Small PR Slices
- PR 1: DHT store admission refinements and tests.
- PR 2: Hidden-service traffic shaping and tests.
- PR 3: Windows installer and firewall setup.
- PR 4: macOS/BSD adapter files.
- PR 5: Browser frontend hardening and local API polish.
