# VX6 Documentation Map

Use this page as the directory. Start with the path for your task. The tree
below is a logical grouping of the current flat file layout (not literal
subdirectories); paths are kept stable so repository links remain valid.

```text
docs/
|-- README.md                    this map and reading paths
|-- Getting Started
|   |-- setup.md                 build, install, initialize, first run
|   |-- usage.md                 common node/service workflows
|   |-- commands.md              command and flag reference
|   |-- LINUX.md                 Linux-specific support and workflow
|   `-- systemd.md               user service workflow
|-- Security and Networking
|   |-- security.md              implemented protections and limitations
|   |-- dataplane-threat-model.md threat model, acceptance checks, issue mapping
|   |-- ipsec.md                 Linux IKEv2/IPsec setup, operation, tests
|   |-- identity.md              node identity and signed records
|   |-- discovery.md              peer discovery
|   |-- dht.md                    DHT behavior and record families
|   `-- services.md              service publication and access model
|-- Development
|   |-- repository-map.md         source tree and ownership boundaries
|   |-- architecture.md           component architecture and packet path
|   |-- sdk.md                    Go SDK status and API
|   |-- PROTOCOL_SDK_NEXT_STEPS.md SDK/protocol planning
|   |-- GUI.md                    desktop interface
|   |-- PROXY.md                  proxy behavior
|   `-- ebpf.md                   experimental eBPF/XDP notes
|-- Operations and Planning
|   |-- packaging-plan.md         Linux and cross-platform packaging plan
|   |-- status.md                 current project status
|   |-- roadmap.md                priority overview
|   |-- TODO_ISSUES.md            task pointers
|   `-- STABLE_RELEASE_POLICY.md  release gates and policy
|-- changes/                      dated change notes
`-- archive/                      historical reports and archived material
```

## Reading Paths

**I want to use VX6:** [setup](setup.md) -> [usage](usage.md) ->
[commands](commands.md).

**I want to understand packet security:** [security status](security.md) ->
[threat model](dataplane-threat-model.md) -> [IPsec guide](ipsec.md).

**I want to develop against VX6:** [repository map](repository-map.md) ->
[architecture](architecture.md) -> [SDK status](sdk.md).

**I want to install or package Linux VX6:** [Linux guide](LINUX.md) ->
[IPsec operations](ipsec.md) -> [packaging plan](packaging-plan.md).

## Current Scope Warning

The verified IKEv2/IPsec dataplane and the capture test are Linux-only. The
Go SDK builds within this repository, but external SDK consumers still need the
public API cleanup tracked by issue #58. The IPsec path uses strongSwan and
Linux kernel XFRM; a production installer is tracked by issue #57. See
[current status](status.md) before relying on platform or feature claims.
