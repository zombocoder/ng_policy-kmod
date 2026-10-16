# Endpoint model

How `ng_policy` identifies the traffic it sees. For the hook-pair
structural decision this all rests on, see
[`architecture.md`](architecture.md#decision-1--an-endpoint-is-a-pair-of-hooks);
for how endpoint IDs are used inside a rule, see
[`policy-model.md`](policy-model.md).

## Identity by explicit registration only

An endpoint does not exist until `NGM_POLICY_ENDPOINT_ADD` says it
does. There is no implicit identity derived from an IP address, a MAC
address, an interface name, or anything else a packet carries — the
node's only notion of "who sent this" is the numeric `endpoint_id`
bound to whichever hook a frame arrived on, and its only notion of
"who is unmapped" is the `EXTERNAL` fallback from the address map (see
[`policy-model.md`](policy-model.md)).

## Reserved IDs and their exact values

```c
#define NG_POLICY_EP_ANY            0x00000000u
#define NG_POLICY_EP_RESERVED_MIN   0xffffff00u
#define NG_POLICY_EP_LOCAL_HOST     0xfffffffdu
#define NG_POLICY_EP_EXTERNAL       0xffffffffu
#define NG_POLICY_EP_ID_MAX         (NG_POLICY_EP_RESERVED_MIN - 1u)  /* 0xfffffeff */
```

`NG_POLICY_EP_ID_VALID(id)` — `id != 0 && id <= 0xfffffeff` — is what
`ENDPOINT_ADD` checks a registered ID against
(`test_endpoint_reserved_id_rejected` proves `ANY`, `EXTERNAL`, and
`LOCAL_HOST` are all rejected as *registerable* IDs with `EINVAL`).
`ANY`, `EXTERNAL`, and `LOCAL_HOST` are reserved precisely so they can
be used as rule-field sentinels ([`policy-model.md`](policy-model.md))
without ever colliding with a real registration.

## `LOCAL_HOST` is never inferred from topology

There is no code path anywhere in `ng_policy` that decides a packet is
"from the local host" based on which hook it arrived on, which
interface is attached, or any other structural signal. **An endpoint is
classified as `LOCAL_HOST` only when userland explicitly maps an IPv4
address to `endpoint_id = NG_POLICY_EP_LOCAL_HOST` in the address map**
(`TX_ADD_ADDR`, validated the same way as any other address entry —
`ngp_tx_validate_refs()`'s address-entry check accepts only an
ordinary registered ID (`NG_POLICY_EP_ID_VALID()`) or `LOCAL_HOST` as
an address-map target; `EXTERNAL` and `ANY` are both rejected `EINVAL`
there, since an address explicitly mapped to `EXTERNAL` would be
redundant with the fallback every unmapped address already gets).
Absent
that explicit mapping, traffic to or from an address the node doesn't
otherwise recognise classifies as `EXTERNAL`, which is the fallback the
requirements permit (design spec §6). If a control plane wants
"traffic to the box itself" treated specially, it must say so in the
address map — the kernel will never guess it from the fact that a
packet's destination happens to be a locally-configured address on the
underlying interface, because `ng_policy` has no visibility into
interface addressing at all; it only sees frames on hooks.

## Two endpoints registering the same hook name

`ENDPOINT_ADD` does **not** reject a second endpoint that names a hook
already claimed by another endpoint — there is no uniqueness check on
`hook`/`peer_hook` across endpoints. What happens instead is
first-match-wins at bind time: `ngp_bind_one()` is called for each
endpoint in registration order when a hook of that name appears
(`ng_policy_hook_attach()` walks `priv->eplist`, which is insertion-
ordered, and stops at the first endpoint whose `hook`/`peer_hook`
matches — see the `break` in the loop). The **first** endpoint
registered with that hook name gets it; the second endpoint's `hp`
field for that hook stays `NULL` forever (unless it is later given a
different, unclaimed hook name via `F_REPLACE`).

This is fail-safe by construction, not merely by accident: an endpoint
with no bound hook has no ingress and no egress, so any traffic that
would have gone to it is instead counted as `unbound_hook_packets` (if
no hook ever connects to it at all) or simply never arrives on its
behalf — it is never silently misattributed to the wrong endpoint's
counters. And it is **detectable**: `ENDPOINT_LIST` reports
`EP_S_CONNECTED`/`EP_S_PEER_CONNECTED` only when `ep->hp`/`ep->peer_hp`
is actually non-NULL, so an endpoint that lost the naming race shows up
in a list response with neither status flag set, distinguishing it from
a correctly bound endpoint at a glance. A control plane that names hooks
carelessly gets a quiet but observable failure, not data crossing
endpoint boundaries.

## Binding is lazy and symmetric

A hook can be connected before or after its endpoint is registered, and
both orders bind correctly:

- **Hook first, endpoint later:** `ng_policy_newhook()` allocates the
  hook's private data with `hp->ep = NULL`; when a later
  `ENDPOINT_ADD` registers a matching `hook`/`peer_hook` name,
  `ngp_rebind_hooks()` walks every existing hook on the node and binds
  the new endpoint against any that match and are still unbound.
- **Endpoint first, hook later:** `ENDPOINT_ADD` registers the
  endpoint with `hp = peer_hp = NULL`; when a hook of the matching name
  connects, `ng_policy_hook_attach()` binds it immediately.

**Rebinding after a disconnect is the same mechanism, not a special
case.** `ng_policy_disconnect()` calls `ng_policy_hook_detach()`, which
clears only the binding (`ep->hp`/`ep->peer_hp` set back to `NULL`) —
the endpoint itself, its counters, and its registration all survive.
If a hook of the same name connects again later, it goes through the
identical "hook first" path above and rebinds to the same, still-live
endpoint, with its accumulated counters intact. Proven by
`test_endpoint_binds_either_order`.

## Flags

```c
#define NG_POLICY_EP_ENABLED    0x00000001u  /* reserved, see below */
#define NG_POLICY_EP_TRUSTED    0x00000002u
#define NG_POLICY_EP_CFG_MASK   0x00000003u

#define NG_POLICY_EP_F_REPLACE  0x00010000u  /* request-only, never stored */

#define NG_POLICY_EP_S_CONNECTED      0x01000000u  /* status-only, kernel-set */
#define NG_POLICY_EP_S_PEER_CONNECTED 0x02000000u  /* status-only, kernel-set */
```

`flags` on the request is masked to `NG_POLICY_EP_CFG_MASK |
NG_POLICY_EP_F_REPLACE` (anything else is `EINVAL`); the stored
`ep->flags` keeps only the config bits (`ENABLED`/`TRUSTED`) and is
reported back verbatim on `ENDPOINT_LIST`, OR'd with the status bits
computed fresh at query time.

**`NG_POLICY_EP_ENABLED` is reserved and deliberately not enforced in
v0.1.** It is stored and reported exactly like `TRUSTED`, but no code
path anywhere in the data plane reads it — an endpoint with the bit
clear behaves identically to one with it set. This was an explicit
ruling during implementation (recorded in the project's SDD ledger,
Ruling R1): the requirements ask only that flags without a clear
enforced semantics be avoided from having one invented, no completion
row covers "disable an endpoint without deleting it," and no
test in the plan exercises enforcement — inventing behaviour nothing
verifies would be worse than leaving the bit reserved. The practical
consequence: a controller that wants to temporarily stop traffic for
one endpoint without losing its counters must delete and re-add it
(losing the registration, though not necessarily the concept — a
future v0.2 could give `ENABLED` real enforcement without an ABI
change, since the bit and its storage already exist).

`TRUSTED` is stored and reported the same way and is likewise not
interpreted by the data plane in v0.1 — it exists as a place for
userland-defined semantics (e.g. a control plane convention for which
endpoints skip some policy layer *it* enforces above this node) without
needing an ABI change later.

## What this document does not cover

The rule-level meaning of endpoint IDs (`ANY`, `EXTERNAL`, wildcards):
[`policy-model.md`](policy-model.md). Per-endpoint counters and their
exact counting points: [`statistics.md`](statistics.md). The two-hook
structural model these endpoints are built from:
[`architecture.md`](architecture.md).
