#!/bin/sh
# Repeated create/destroy and load/unload cycles.  The malloc type must
# return to zero in use, or something is leaking.
set -e

MOD=${1:-./sys/netgraph/ng_policy/ng_policy.ko}
CYCLES=${2:-50}

# Raw reading, for the human-readable log lines below: vmstat -m omits a
# malloc type entirely until it has had at least one allocation request,
# so this can be blank right after a fresh kldload with nothing done yet.
usage() { vmstat -m | awk '$1 == "ng_policy" { print $2, $3 }'; }

# Same reading, normalised to "<inuse> <bytes>" -- "0 0" when the type
# has no row yet -- so the before/after comparison at the end is a real
# number-to-number check instead of comparing a number against blank.
usage_n() {
    u=$(usage)
    if [ -z "$u" ]; then
        echo "0 0"
    else
        echo "$u"
    fi
}

kldunload ng_policy 2>/dev/null || true
kldload "$MOD"

before=$(usage_n)
echo "after load:   $(usage)"

i=0
while [ $i -lt "$CYCLES" ]; do
    ngctl -f - <<EOF >/dev/null
mkpeer policy ctl ctl0
name .:ctl leakn
msg leakn: endpointadd { endpoint_id=1001 hook="ep-1001" peer_hook="fab-1001" }
msg leakn: endpointadd { endpoint_id=2001 hook="ep-2001" peer_hook="fab-2001" }
shutdown leakn:
EOF
    i=$((i + 1))
done
sleep 2

after=$(usage_n)
echo "after $CYCLES cycles: $(usage)"

# kldunload is left unguarded (no "|| true"): a leaked node *reference*
# makes the module busy, the kernel refuses to unload it, and "set -e"
# aborts this script right here with a non-zero exit.  That is separate
# from the in-use comparison below, which is the only thing here that
# catches leaked *memory* -- a pure malloc-type leak does not by itself
# block kldunload; the kernel warns and unloads anyway.
kldunload ng_policy
echo "after unload: $(usage)   (expect empty)"

before_inuse=${before%% *}
after_inuse=${after%% *}
if [ "$before_inuse" != "$after_inuse" ]; then
    echo "FAIL: ng_policy in-use count went from $before_inuse to" \
        "$after_inuse over $CYCLES cycles -- leak" >&2
    exit 1
fi
echo "PASS: ng_policy in-use count stable at $before_inuse across" \
    "$CYCLES cycles"
