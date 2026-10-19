# VX6 SDK

VX6 now exposes an app-facing SDK package at:

- `github.com/vx6/vx6/sdk`

**Current integration status:** this package compiles and its tests pass inside
the VX6 repository, but it is not yet a supported external-app SDK. Some
exported APIs use `internal/config` types, and Go does not allow applications
outside this module to import those types. The examples below therefore show
the current in-repository API shape, not a verified external consumer. Do not
build a third-party integration against it until the public-type cleanup and
external-module test in [issue #58](https://github.com/ethical-buddy/vx6/issues/58)
are complete.

The SDK wraps the existing protocol/runtime so tools and applications can build on VX6 without shelling out to the CLI.

## Core APIs

- `sdk.New(configPath string) (*sdk.Client, error)`
- `(*Client).Init(ctx, sdk.InitOptions) (identity.Identity, error)`
- `(*Client).StartNode(ctx, logWriter, sdk.StartOptions) error`
- `(*Client).AddPeer(name, addr string) error`
- `(*Client).AddService(name string, entry config.ServiceEntry) error`
- `(*Client).RemoveService(name string) error`
- `(*Client).ListServices() (map[string]config.ServiceEntry, error)`
- `(*Client).ResolveService(ctx, service string) (record.ServiceRecord, error)`
- `(*Client).StartForwarder(ctx, sdk.ConnectOptions, sdk.ForwarderCallbacks) (*sdk.ForwarderHandle, error)`
- `(*Client).ObserveStatus(ctx, sdk.StatusObserverOptions) error`
- `sdk.NormalizeHiddenServiceEntry(entry config.ServiceEntry) (config.ServiceEntry, error)`

## Minimal Example

```go
package main

import (
	"context"
	"log"
	"os"

	"github.com/vx6/vx6/internal/config"
	"github.com/vx6/vx6/sdk"
)

func main() {
	ctx := context.Background()
	client, err := sdk.New("")
	if err != nil {
		log.Fatal(err)
	}

	_, err = client.Init(ctx, sdk.InitOptions{
		Name:       "app-node",
		ListenAddr: "[::]:4242",
	})
	if err != nil {
		log.Fatal(err)
	}

	entry, err := sdk.NormalizeHiddenServiceEntry(config.ServiceEntry{
		Target:   "127.0.0.1:8080",
		IsHidden: true,
		Alias:    "app-hidden",
	})
	if err != nil {
		log.Fatal(err)
	}
	if err := client.AddService("app", entry); err != nil {
		log.Fatal(err)
	}

	if err := client.StartNode(ctx, os.Stdout, sdk.StartOptions{}); err != nil {
		log.Fatal(err)
	}
}
```

## Embedded Forwarder Example

```go
handle, err := client.StartForwarder(ctx, sdk.ConnectOptions{
	Service: "alice.ssh",
	Listen:  "127.0.0.1:2222",
	Proxy:   true,
}, sdk.ForwarderCallbacks{
	OnStarted: func(local, svc string) { log.Printf("forwarder started %s -> %s", local, svc) },
	OnError:   func(err error) { log.Printf("forwarder error: %v", err) },
	OnStopped: func() { log.Printf("forwarder stopped") },
})
if err != nil { panic(err) }

// ... run app ...
handle.Stop()
```

## Runtime Status Observer

```go
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

go func() {
	_ = client.ObserveStatus(ctx, sdk.StatusObserverOptions{
		Interval: 2 * time.Second,
		OnStatus: func(s runtimectl.Status) {
			log.Printf("nodes=%d services=%d dht_keys=%d", s.RegistryNodes, s.RegistryServices, s.DHTTrackedKeys)
		},
		OnError: func(err error) {
			log.Printf("status observer error: %v", err)
		},
	})
}()
```

## Notes

- SDK APIs intentionally mirror current CLI/runtime behavior.
- Existing `cmd/vx6` and `cmd/vx6-gui` behavior remains unchanged.
- The SDK package is the intended integration surface, but external app/tool
  support is pending issue #58.
- IPsec-backed service connectivity requires the installed privileged
  `vx6-ipsecd` service on Linux; embedding the SDK does not embed or replace
  that service or the system IKE implementation.
