# ng_policy

A FreeBSD [Netgraph](https://man.freebsd.org/netgraph/4) node type that
filters Ethernet frames between pairs of hooks, using a precompiled rule
set that is swapped in atomically.

You put an `ng_policy` node on the wire between a workload (a jail, a VM,
an interface) and whatever it connects to. Every frame is matched against
the active rules and either forwarded to the other side or dropped. Rules
are loaded over the node's control socket, from `ngctl` or from your own
program via `libnetgraph`.

## Features

- **Endpoints are hook pairs.** Each endpoint has a workload hook and a
  fabric hook; an allowed frame always leaves through the other hook of
  the same endpoint. The node filters, it never switches.
- **Simple, predictable rules.** Match on source/destination endpoint,
  protocol, port ranges and ICMP type/code. Lower priority runs first,
  first match wins, anything unmatched takes the default action.
- **IPv4 address map.** Addresses resolve to endpoint IDs; unknown
  addresses resolve to a reserved `EXTERNAL` endpoint you can write
  rules against.
- **Atomic generations.** Rules and addresses are staged in a
  transaction and committed as one immutable snapshot. A packet never
  sees half an update, and concurrent writers get `ESTALE` instead of
  overwriting each other.
- **Three modes.** `ENFORCE`, `PERMISSIVE` (count would-be drops, pass
  everything) and `DISABLED`.
- **Fail-closed.** A new node drops everything until you commit a
  policy.
- **Counters** per node, per endpoint and per rule.

## Requirements

- FreeBSD 14.3 or later (tested on 14.3-RELEASE, amd64)
- Kernel sources in `/usr/src`
- Root, via `doas` or `sudo`, to load the module and run the tests

## Build and install

```sh
make                 # module, man page and test programs
doas make install    # module to /boot/modules, man page to man4
doas kldload ng_policy
man 4 ng_policy
```

To try it without installing, load the module straight from the build
tree:

```sh
make -C sys/netgraph/ng_policy
doas kldload ./sys/netgraph/ng_policy/ng_policy.ko
```

## Quick start

Create a node, register two endpoints, allow HTTPS from one to the other
(and the replies back), and commit:

```sh
doas ngctl -f - <<'EOF'
mkpeer policy ctl ctl0
name .:ctl pol0
msg pol0: endpointadd { endpoint_id=1001 hook="ep-1001" peer_hook="fab-1001" }
msg pol0: endpointadd { endpoint_id=2001 hook="ep-2001" peer_hook="fab-2001" }
msg pol0: txbegin { }
msg pol0: txaddrule { tx_id=1 nrules=2 rules=[ { rule_id=1 src_endpoint=1001 dst_endpoint=2001 src_port_min=0 src_port_max=65535 dst_port_min=443 dst_port_max=443 priority=10 flags=0 protocol=6 action=1 icmp_type=0 icmp_code=0 } { rule_id=2 src_endpoint=2001 dst_endpoint=1001 src_port_min=443 src_port_max=443 dst_port_min=0 dst_port_max=65535 priority=10 flags=0 protocol=6 action=1 icmp_type=0 icmp_code=0 } ] }
msg pol0: txaddaddr { tx_id=1 naddrs=1 addrs=[ { ipv4=10.0.0.5 endpoint_id=1001 } ] }
msg pol0: txsetdefault { tx_id=1 default_action=2 }
msg pol0: txcommit { tx_id=1 base_generation=0 }
msg pol0: getstats
EOF
```

`action=1` is ALLOW, `action=2` is DROP, `protocol=6` is TCP.

Two things that surprise people the first time:

- **Nothing passes until you commit.** A new node starts at generation 0
  with a default action of DROP.
- **The node goes away when `ngctl` exits.** A node with no hooks left
  removes itself, so run a multi-step session as one script, or keep a
  data hook connected.

The policy is stateless: allowing `A -> B` does not allow the reply
`B -> A`, which is why the example has two rules.

More worked sessions, with real output:
[`docs/ngctl-examples.md`](docs/ngctl-examples.md).

## How it fits together

```
  workload side                 ng_policy                 fabric side
                       +-------------------------+
  jail / VM / iface ---| ep-1001 <---> fab-1001  |--- ng_bridge, ng_ether,
  jail / VM / iface ---| ep-2001 <---> fab-2001  |    another node, ...
                       |                         |
                       |  rules + address map    |
                       |  (one generation)       |
                       +-------------------------+
                                   ^
                                   |  control messages
                          ngctl or libnetgraph
```

The module only enforces. Deciding what the rules should say, and which
endpoint ID belongs to what, is left to whatever program drives it. See
[`docs/architecture.md`](docs/architecture.md).

## Running the tests

```sh
make -C tests
doas kldload ./sys/netgraph/ng_policy/ng_policy.ko
doas ./tests/ngp_test                  # 62 run, 0 failed
doas ./tests/ngp_fuzz 12345 200000     # seeded fuzzing, control and packet paths
doas sh tests/ngp_stress.sh ./sys/netgraph/ng_policy/ng_policy.ko 50
doas ./tests/ngp_bench                 # commit and lookup benchmarks
doas kldunload ng_policy
vmstat -m | grep -c ng_policy          # 0 means nothing leaked
```

Use a VM or a machine you can afford to panic. If `ngp_test` can't run
(module not loaded, not root), it says why and exits 2.

## Documentation

Start with the man page, [`ng_policy(4)`](man/ng_policy.4): node type,
hooks, modes, every control message, sysctls and error codes.

| Document | Covers |
|---|---|
| [`architecture.md`](docs/architecture.md) | The node model, why an endpoint is a hook pair, node lifecycle |
| [`packet-path.md`](docs/packet-path.md) | What happens to each kind of frame: allowed, denied, unknown, ARP, fragments, malformed |
| [`policy-model.md`](docs/policy-model.md) | Rules, wildcards, priority, generations, the lookup structure |
| [`endpoint-model.md`](docs/endpoint-model.md) | Endpoint IDs, reserved IDs, hook binding |
| [`control-api.md`](docs/control-api.md) | Wire structs, errno values, batching and paging limits |
| [`ngctl-examples.md`](docs/ngctl-examples.md) | Executed `ngctl` sessions with real output |
| [`concurrency.md`](docs/concurrency.md) | Why a policy swap is safe, and what the net epoch is for |
| [`statistics.md`](docs/statistics.md) | Every counter and where it is counted |
| [`security.md`](docs/security.md) | Input validation, threat list, known limits of the testing |
| [`performance.md`](docs/performance.md) | Measured commit and lookup costs |
| [`verification.md`](docs/verification.md) | Each property the module claims, and the test that shows it |
| [`development.md`](docs/development.md) | Source layout, full test sequence, adding a control message |
| [`phase0-single-host-fabric.md`](docs/phase0-single-host-fabric.md) | A single-host walkthrough with epair/tap endpoints in VNET jails |

## Status and limitations

v0.1. IPv4 only, stateless, and VLAN-tagged frames are not inspected
(they take the configurable `unsupported_action`). Throughput on real
NICs has not been measured yet. A port skeleton for `net/ng-policy`
lives in [`port/`](port/); see [`port/README.md`](port/README.md) for
what is still missing.

## Contributing

Bug reports and patches are welcome. See
[`CONTRIBUTING.md`](CONTRIBUTING.md) for what a change needs to pass,
and [`SECURITY.md`](SECURITY.md) for reporting vulnerabilities
privately. Participation is covered by the
[code of conduct](CODE_OF_CONDUCT.md).

## License

BSD-2-Clause. See [`LICENSE`](LICENSE).
