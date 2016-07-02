#!/bin/sh
# this script tests basic udpastcp functionality.

test1() {
    (
        pids=
        trap 'kill $pids' EXIT
        ./udpastcp client localhost 36563 localhost 64109 &
        pids="$!"
        ./udpastcp server localhost 64109 localhost 41465 &
        pids+=" $!"
        ( ( sleep 0.2; echo BBBBBBBB; ) | socat udp6-listen:41465 - ) &
        pids+=" $!"
        ( ( sleep 0.1; echo AAAAAAAA; ) | socat - 'udp-connect:[::1]:36563' ) &
        pids+=" $!"
        sleep 0.3
    )
}

nl='
'

if [ "$( test1 )" = "AAAAAAAA${nl}BBBBBBBB" ]; then
    echo "Test succeeded."
else
    echo "Test failed."
    exit 1
fi
