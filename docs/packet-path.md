# Packet path

This document walks every outcome `ng_policy_rcvdata()` can produce, one
case at a time, each with its own flow. The full decision function is
`ngp_decide()` in `src/ng_policy.c`; parsing is
`ng_policy_parse()` in `ng_policy_packet.c`; matching is
`ng_policy_match()` in `ng_policy_policy.c`. For the rule semantics
(priority, wildcards, statelessness) see
[`policy-model.md`](policy-model.md); for what each counter means see
[`statistics.md`](statistics.md).

## Shared entry sequence

Every frame goes through the same prologue before any of the eight
cases below diverge, inside one `NET_EPOCH_ENTER`/`EXIT` section
(see [`concurrency.md`](concurrency.md) for why that is safe against a
concurrent commit):

```
rcvdata(hook, item)
  hp = hook's private data
  ep = hp->ep                     (NULL if the hook binds no endpoint)
  |
  +-- ep == NULL --------------------------------> DROP, unbound_hook_packets++
  |
  packets_total++, bytes_total += len
  out = (hp->side == EP) ? ep->peer_hp->hook : ep->hp->hook
  +-- out == NULL (no partner hook) ---------------> DROP, no_peer_packets++
  |
  +-- mode == DISABLED ----------------------------> FORWARD, no lookup at all
  |
  ngp_decide(...)   <- the eight cases below
  |
  enforce = (mode == ENFORCE) ? decision : ALLOW
  +-- decision == DROP && mode == PERMISSIVE ------> permissive_violations++,
  |                                                    ep->violations++
  +-- enforce == ALLOW -----------------------------> FORWARD
  +-- enforce == DROP ------------------------------> DROP
```

A policy DROP is not an error: the frame is freed and `rcvdata` returns
`0` to Netgraph either way (a DROP is a successful decision, not a
failure).

---

## 1. Allowed local packet

Both endpoints are known to the node — the ingress hook fixes one side,
the address map resolves the other to a *registered* endpoint ID — and
a rule (or the default action) says ALLOW.

```
ep-1001 --TCP 443--> [ng_policy]            src=1001 (from hook)
                          |                  dst=addr_map(10.50.2.16)=2001
                          v                  match: rule_id=1, ALLOW
                       fab-1001 ------------> forwarded, allowed_packets++
```

Proven by `test_forward_ep_to_fab` / `test_forward_fab_to_ep` (basic
forwarding both directions) and `test_policy_matrix` /
`test_addr_map_resolves_destination` (address-map-mediated ALLOW with a
matching rule).

## 2. Denied packet

Same resolution as case 1, but the matching rule (or the default
action) is DROP.

```
ep-1001 --TCP 80--> [ng_policy]             src=1001, dst=2001
                          |                  no rule matches TCP/80
                          v                  default_action = DROP
                        (freed) -----------> dropped_packets++
```

Proven by `test_policy_matrix` (the `1001 -> 2001 TCP/80 DROP` row of
the requirements' matrix) and `test_enforce_semantics`.

## 3. Unknown destination (address not in the map)

Ingress on the workload hook fixes `src_endpoint`. The destination
address is looked up in the generation's address map
(`ng_policy_addr_lookup()`); when it is not present, the lookup falls
back to `NG_POLICY_EP_EXTERNAL` (`0xffffffff`) rather than failing —
there is no "address not found" error, only a classification. A rule
written for a *specific* registered destination endpoint then does not
match, and the packet falls through to the default action (or to a
rule that explicitly targets `EXTERNAL` — see case 4).

```
ep-1001 --TCP 443--> [ng_policy]            src=1001 (from hook)
        (dst 10.50.99.99, never mapped)     dst=addr_map(10.50.99.99)
                          |                    = EXTERNAL (lookup miss)
                          v                  rule for dst=2001 does not match
                       default_action -----> (DROP by default)
```

Proven directly by `test_addr_map_resolves_destination`, which installs
a rule matching `dst_endpoint=2001` and an address map that does *not*
cover `10.50.153.153`, then confirms the same TCP flow that passes
against the mapped address is dropped against the unmapped one — the
comment there reads "unmapped destination: resolves to EXTERNAL, no
match."

## 4. External destination (rule written against `EXTERNAL`)

`EXTERNAL` is not only a fallback value — it is a legal `src_endpoint`
or `dst_endpoint` in a rule (`ngp_endpoint_ref_ok()` in
`ng_policy_policy.c` accepts `NG_POLICY_EP_ANY`, `NG_POLICY_EP_EXTERNAL`
and `NG_POLICY_EP_LOCAL_HOST` alongside ordinary registered IDs). A
control plane can therefore compile an explicit rule such as
`src_endpoint=1001, dst_endpoint=EXTERNAL, action=ALLOW` — "endpoint
1001 may reach anything not in the address map" — and it participates
in ordinary priority-ordered matching exactly like a rule naming two
registered endpoints.

```
ep-1001 --TCP 443--> [ng_policy]            src=1001
        (dst unmapped -> EXTERNAL)          dst=EXTERNAL (lookup miss)
                          |                  rule: src=1001 dst=EXTERNAL ALLOW
                          v                    matches
                       fab-1001 ------------> forwarded, allowed_packets++
```

This is the same address-resolution mechanism as case 3 — the
difference is entirely in what the *policy* does with the resulting
`EXTERNAL` classification, not in a different code path. It is exact
by construction: `ng_policy_addr_lookup()` is the single function used
for both hook directions (`ngp_decide()` calls it identically whether
resolving `src_endpoint` on fabric-side ingress or `dst_endpoint` on
workload-side ingress), so the fallback-to-`EXTERNAL` behaviour proven
for the destination side by `test_addr_map_resolves_destination` holds
symmetrically for the source side. `ngp_endpoint_ref_ok()` accepting
`EXTERNAL` as a rule field is exercised implicitly by any commit that
uses it and is not rejected; there is no dedicated test that installs a
rule naming `EXTERNAL` explicitly and sends a matching packet through
it — see the completion-criteria table in the top-level `README.md` for
this noted as a documentation-time gap rather than a silent claim.

## 5. ARP

ARP is not IPv4 and carries no L4 information, so it is never subject
to rule matching at all. `ng_policy_parse()` recognises
`ETHERTYPE_ARP` before ever touching an IP header and returns
`NG_POLICY_PARSE_ARP` immediately; `ngp_decide()` routes it straight to
`cfg.arp_action` (default `ALLOW`) without loading the snapshot or
touching the address map.

```
ep-1001 --ARP-------> [ng_policy]           EtherType == ARP
                          |                  arp_packets++
                          v
                       cfg.arp_action -----> ALLOW by default
```

Blocking ARP under a default-DROP policy would break basic reachability
in ways that are hard to diagnose, which is why the default differs
from every other unmatched-traffic action. Proven by `test_arp_action`
(both `arp_action=ALLOW` and `arp_action=DROP`, with the counter
checked).

## 6. Fragment (non-initial)

A non-zero IP fragment offset means the transport header does not
exist in this frame — there is nothing to match a port range or ICMP
type against — so `ng_policy_parse()` returns
`NG_POLICY_PARSE_FRAGMENT` before attempting to read one, and
`ngp_decide()` routes it to `cfg.frag_action` (default `DROP`) without
ever reaching rule matching. A *first* fragment (`IP_MF` set, offset
zero) has a real transport header and parses and matches normally —
it does not take `frag_action` at all, though it still increments
`fragmented_packets`.

```
ep-1001 --IP frag, offset>0--> [ng_policy]  no transport header available
                                    |        fragmented_packets++
                                    v
                                cfg.frag_action -> DROP by default,
                                                    never reaches ng_policy_match()
```

Proven by `test_fragment_action`: a non-initial fragment is dropped
under `frag_action=DROP` and forwarded under `frag_action=ALLOW`; a
first fragment (`IP_MF` set) passes under default `ALLOW` because it
matched normally, not because of `frag_action`.

## 7. Malformed packet

Anything that fails a bounds or field-sanity check — a truncated
Ethernet header, a missing or too-short IPv4 header, `ip_v != 4`, an
IHL below the 20-byte minimum, `ip_len` smaller than the header it
claims, or a transport header that does not fit the claimed IP payload
— is `NG_POLICY_PARSE_MALFORMED`. Every check in
`ng_policy_parse()` happens before a single byte past `m_pkthdr.len`
is read (see [`security.md`](security.md) for the bounds-safety
argument); a malformed packet takes `cfg.malformed_action` (default
`DROP`) without ever reaching rule matching.

```
ep-1001 --garbled IPv4--> [ng_policy]       IHL < 5, or ip_len < IHL, or
                              |               truncated transport header, ...
                              v              malformed_packets++
                          cfg.malformed_action -> DROP by default
```

Proven by `test_malformed_packets`, which exercises five distinct
malformation shapes (truncated Ethernet header, Ethernet-only frame,
undersized IHL, wrong IP version, undersized `ip_len`) plus
`test_ip_options` (a longer-than-minimum IHL, which is *not*
malformed — it is a valid, if unusual, header) and
`test_debug_force_copy_path` (the same set of cases through the
non-contiguous-mbuf copy path via
`net.graph.policy.debug_force_copy`).

## 8. Permissive violation

`PERMISSIVE` mode evaluates the decision exactly as `ENFORCE` would,
but always forwards, crediting a violation only when the decision was
DROP. This applies uniformly to every one of cases 2-7 — a permissive
violation is not limited to ordinary rule-based DROPs; malformed
packets, unsupported EtherTypes, fragments, and ARP under `arp_action
= DROP` all count as violations too when their configured action is
DROP, because "observe only" has to mean *every* would-be-DROP outcome
is observed, not just the ones that reached rule matching.

```
ep-1001 --TCP 80--> [ng_policy]             would-be decision: DROP
                          |                  mode == PERMISSIVE
                          v
                       fab-1001 ------------> forwarded anyway,
                                               permissive_violations++,
                                               ep->violations++,
                                               dropped_packets NOT incremented
```

Proven by `test_permissive_semantics` (an ordinary rule-DROP forwarded
with a violation counted, both at the node and the endpoint level via
`GET_ENDPOINT_STATS`) and `test_permissive_covers_parse_categories`
(an ARP frame with `arp_action=DROP` under `PERMISSIVE` — forwarded,
violation counted, `dropped_packets` untouched — proving the "applies
uniformly" claim above rather than asserting it).

---

## Unknown IPv4 protocols are matched, not "unsupported"

One rule that touches several of the cases above and is easy to get
backwards: an IPv4 packet carrying a protocol number other than TCP,
UDP, or ICMP (GRE, ESP, OSPF, ...) is **not** `PARSE_UNSUPPORTED`. It
parses successfully, with `src_port`/`dst_port` left at zero, and is
matched against the rule set exactly like TCP or UDP — a rule with
`protocol=47` matches GRE. `unsupported_action` applies only to
non-IPv4, non-ARP **EtherTypes** — case 5's sibling for anything that
isn't ARP or IPv4 at the Ethernet level, VLAN (`ETHERTYPE_VLAN`/802.1Q)
included in v0.1 (see `test_unsupported_ethertype`).

The reason is stated directly in `ng_policy_packet.c`'s comment on the
protocol switch's `default` case: routing an unrecognised **IP**
protocol through unsupported-EtherType handling would let a single
`unsupported_action = allow` silently bypass policy for every
non-TCP/UDP/ICMP protocol at once — GRE tunnels, ESP, OSPF, everything
— rather than leaving each one subject to whatever rule (or default
action) a control plane chooses to write for it. Proven by
`test_unknown_ip_protocol_is_matched`.
