# `ngctl` examples

> **Fail-closed by default.** A freshly constructed `ng_policy` node starts
> at generation 0 with `default_action = DROP` and `mode = ENFORCE`. Combined
> with the `DISABLED` mode as the explicit escape hatch, this means an
> unconfigured node **blocks all traffic** rather than silently permitting
> it. If you connect hooks to a brand-new node and nothing seems to pass,
> this is why: no policy generation has been committed yet. Begin a
> transaction, set a default action, and commit it before expecting traffic
> to flow.

Every command block below was actually run against a built
`ng_policy.ko` on this host and its real output is pasted in verbatim.
For the wire format behind each message see
[`control-api.md`](control-api.md).

## A note before the first example: control-only sessions are ephemeral

A `ng_policy` node's `disconnect` hook calls `ng_rmnode_self()` once the
node has zero attached hooks — standard Netgraph node behaviour, not
anything specific to this module. A bare `ngctl -f -` script that only
does `mkpeer policy ctl ctl0` (one control hook, no data hooks) creates
a node that is torn down **the moment the `ngctl` process exits and
closes that socket**, because closing the socket disconnects `ctl0`,
dropping the node's hook count to zero. This means a multi-step
`ngctl` session against one node has to run as **one script** (or keep
a data hook connected some other way) — you cannot create a node in
one `ngctl -f -` invocation, note its `tx_id`, and reference it from a
second, later invocation, because the node is already gone. Every
example below that needs more than one message is therefore one
continuous script.

## Example 1: a fresh node's fail-closed defaults

```sh
doas ngctl -f - <<'EOF'
mkpeer policy ctl ctl0
name .:ctl pol0
msg pol0: getconfig
msg pol0: getstats
shutdown pol0:
EOF
```

Real output:

```
Rec'd response "getconfig" (1) from "[2225]:":
Args:	{ version=1 mode=2 arp_action=1 frag_action=2 unsupported_action=2 malformed_action=2 }
Rec'd response "getstats" (13) from "[2225]:":
Args:	{ mode=2 policy_memory=112 endpoint_memory=8192 }
```

`mode=2` is `NG_POLICY_MODE_ENFORCE` and `getstats` shows no
`generation`, `packets_total`, or any other field at zero — this is
`ngctl`'s ASCII printer, which (via `ng_parse`'s generic struct
`unparse`) **skips any field equal to its type's default value**, which
is `0` for every integer field here. A field silently missing from
printed output almost always means "it's zero," not "it's missing from
the struct" — cross-check against the struct definitions in
[`control-api.md`](control-api.md) if that is ever ambiguous.
`policy_memory=112` is the empty (generation-0) snapshot's `memsize`; no
rules, no addresses, `default_action = DROP` (not itself visible in
`getstats`, but see Example 2 for confirming it in effect).

## Example 2: full walkthrough — create, register endpoints, install a generation, read statistics, switch modes, tear down

```sh
doas ngctl -f - <<'EOF'
mkpeer policy ctl ctl0
name .:ctl pol0
msg pol0: setmode { mode=2 }
msg pol0: endpointadd { endpoint_id=1001 hook="ep-1001" peer_hook="fab-1001" }
msg pol0: endpointadd { endpoint_id=2001 hook="ep-2001" peer_hook="fab-2001" }
msg pol0: txbegin { }
msg pol0: txaddrule { tx_id=1 nrules=2 rules=[ { rule_id=1 src_endpoint=1001 dst_endpoint=2001 src_port_min=0 src_port_max=65535 dst_port_min=443 dst_port_max=443 priority=10 flags=0 protocol=6 action=1 icmp_type=0 icmp_code=0 } { rule_id=2 src_endpoint=2001 dst_endpoint=1001 src_port_min=443 src_port_max=443 dst_port_min=0 dst_port_max=65535 priority=10 flags=0 protocol=6 action=1 icmp_type=0 icmp_code=0 } ] }
msg pol0: txaddaddr { tx_id=1 naddrs=1 addrs=[ { ipv4=10.0.0.5 endpoint_id=1001 } ] }
msg pol0: txsetdefault { tx_id=1 default_action=2 }
msg pol0: txcommit { tx_id=1 base_generation=0 }
msg pol0: getstats
msg pol0: getrulestats { }
msg pol0: endpointlist { }
msg pol0: setmode { mode=1 }
msg pol0: getconfig
shutdown pol0:
EOF
```

Real output (in order):

```
Rec'd response "txbegin" (7) from "[2222]:":
Args:	{ tx_id=1 generation=1 timeout=60 }
Rec'd response "txcommit" (11) from "[2222]:":
Args:	{ generation=1 memory=472 build_usec=2039 validate_usec=105 commit_usec=8 reclaim_usec=20 nrules=2 naddrs=1 }
Rec'd response "getstats" (13) from "[2222]:":
Args:	{ generation=1 commits=1 mode=2 nendpoints=2 nrules=2 naddrs=1 policy_memory=472 endpoint_memory=8576 addr_memory=128 }
Rec'd response "getrulestats" (15) from "[2222]:":
Args:	{ generation=1 total=2 returned=2 next_index=2 entries=[ { rule={ rule_id=1 src_endpoint=1001 dst_endpoint=2001 src_port_max=65535 dst_port_min=443 dst_port_max=443 priority=10 protocol=6 action=1 } } { rule={ rule_id=2 src_endpoint=2001 dst_endpoint=1001 src_port_min=443 src_port_max=443 dst_port_max=65535 priority=10 protocol=6 action=1 } index=1 } ] }
Rec'd response "endpointlist" (6) from "[2222]:":
Args:	{ generation=1 total=2 returned=2 next_index=2 entries=[ { endpoint_id=1001 hook="ep-1001" peer_hook="fab-1001" } { endpoint_id=2001 hook="ep-2001" peer_hook="fab-2001" } ] }
Rec'd response "getconfig" (1) from "[2222]:":
Args:	{ version=1 mode=1 arp_action=1 frag_action=2 unsupported_action=2 malformed_action=2 }
```

Every reply printed as readable ASCII (no hex fallback anywhere in this
run, which would indicate a `TYPE_INFO` macro missing a field). Notes
on reading this output against `getrulestats`' zero-suppression: the
second rule entry shows `index=1` (nonzero, so printed) but the first
does not show `index=0` (suppressed, per Example 1's note); likewise
neither entry shows `match_packets`/`match_bytes`, both genuinely zero
since no traffic was sent through this control-only session. `txbegin`
returned `tx_id=1` for this freshly created node — the first
transaction on a fresh node is always `tx_id=1`, which is what makes it
safe to hard-code `tx_id=1` in every later message of this same script
without first parsing the `txbegin` reply back out of `ngctl`'s text
output.

## Example 3: errors — `EEXIST` and `ESTALE`

A duplicate endpoint ID without `F_REPLACE`:

```sh
doas ngctl -f - <<'EOF'
mkpeer policy ctl ctl0
name .:ctl pol0
msg pol0: endpointadd { endpoint_id=1001 hook="ep-1001" peer_hook="fab-1001" }
msg pol0: endpointadd { endpoint_id=1001 hook="ep-x" peer_hook="fab-x" }
EOF
```

```
ngctl: send msg: File exists
ngctl: line 4: error in file
```

`ngctl -f -` aborts the whole script at the first message that fails —
later lines (including any `shutdown`) never run. In this example the
node still self-destructs on script exit anyway (see the note above),
but a script that connects real data hooks before hitting an error
would leave a live node behind, worth remembering when scripting
against a persistent node.

A commit against a generation that has already moved on:

```sh
doas ngctl -f - <<'EOF'
mkpeer policy ctl ctl0
name .:ctl pol0
msg pol0: txbegin { }
msg pol0: txsetdefault { tx_id=1 default_action=2 }
msg pol0: txcommit { tx_id=1 base_generation=5 }
EOF
```

```
Rec'd response "txbegin" (7) from "[2229]:":
Args:	{ tx_id=1 generation=1 timeout=60 }
ngctl: send msg: Stale NFS file handle
ngctl: line 5: error in file
```

`ESTALE`'s standard C errno string on this system is "Stale NFS file
handle" — nothing to do with NFS here, just the generic libc message
for that errno number; `txcommit` correctly rejected `base_generation=5`
against an active generation of `0` (this node had never committed
anything, so `base_generation` must be `0` to succeed, not any other
value, "stale or not" — see [`control-api.md`](control-api.md) for
optimistic concurrency).

## `ngctl`'s own parser versus `NgSendAsciiMsg` from C

Every example above uses **bare-word syntax** for `mkpeer`/`name`/
`connect` (`mkpeer policy ctl ctl0`, `name .:ctl pol0`) — `ngctl`
parses these top-level directives itself, before any `ng_parse`
machinery is involved, so no braces are needed. `msg` arguments, by
contrast, go through the real kernel ASCII-to-binary path
(`NGM_ASCII2BINARY`, `ng_parse_struct`) and need the brace syntax shown
throughout this document: `{ field="value" field2=123 }`. If you are
instead calling `NgSendAsciiMsg()` directly from a C program (as
opposed to typing into `ngctl`), the **entire** message — not just the
`msg`-style arguments — has to be the brace-delimited struct form,
because `NgSendAsciiMsg()` has no separate bare-word front end the way
`ngctl` does for its own directives; it hands your string straight to
the same `ng_parse_struct`-based conversion `ngctl`'s `msg` command
uses internally.
