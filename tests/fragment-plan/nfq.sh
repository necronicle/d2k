#!/bin/sh
# Invoked only inside the disposable network-none container by the runner.
set -eu
iptables -t mangle -A POSTROUTING -p udp -s 10.78.0.2 -d 10.77.0.2 \
    --sport 54000 --dport 54321 -m mark ! --mark 45 -j NFQUEUE --queue-num 2101
ip link add d2k-limit type dummy
ip link set d2k-limit mtu 1100 up
run_case() {
    shape=$1 fake=$2 mode=$3
    /w/raw-test plan "$shape" "$fake" /tmp/plan.tlv
    iface=d2k-out
    if [ "$mode" = mtu ]; then iface=d2k-limit; fi
    D2K_TEST_FAULT="$mode" /w/d2kd-test --queue 2101 --plan /tmp/plan.tlv \
        --mode apply --mark 45 --iface "$iface" --stats 0 --journal 64 \
        --control /tmp/ctl.sock --duration 10 > /tmp/daemon.log 2>&1 &
    daemon=$!
    # Socket creation occurs after queue bind and before entering the loop.
    count=0
    while [ ! -S /tmp/ctl.sock ]; do
        if ! kill -0 "$daemon" 2>/dev/null || [ "$count" -ge 100 ]; then
            cat /tmp/daemon.log; return 1
        fi
        count=$((count+1)); sleep 0.02
    done
    result=0
    /w/raw-test nfq "$shape" "$fake" "$mode" || result=$?
    kill -INT "$daemon"
    wait "$daemon" || result=1
    cat /tmp/daemon.log
    if [ "$mode" = ok ]; then
        grep -q 'ДОИСПОЛНЕН 1' /tmp/daemon.log || result=1
    else
        grep -q 'ДОИСПОЛНЕН 0' /tmp/daemon.log || result=1
        if [ "$mode" = partial ]; then
            grep -q 'поток испорчен' /tmp/daemon.log || result=1
        elif [ "$mode" = mtu ]; then
            grep -q 'посылка 1220 байт при пределе 1100' /tmp/daemon.log || result=1
        elif [ "$mode" = setupfail ]; then
            grep -q 'fragment socket setup:' /tmp/daemon.log || result=1
        fi
    fi
    return "$result"
}
for fake in 0 1; do
    for shape in 1 2 3 4; do run_case "$shape" "$fake" ok; done
done
for mode in mtu setupfail partial; do run_case 2 1 "$mode"; done
