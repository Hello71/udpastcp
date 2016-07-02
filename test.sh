#!/bin/sh
# this script tests basic udpastcp functionality.
if (
pids=
trap 'kill $pids' EXIT
./udpastcp client localhost 36563 localhost 64109 &
pids="$!"
./udpastcp server localhost 64109 localhost 41465 &
pids+=" $!"
socat udp6-listen:41465 - &
pids+=" $!"
( sleep 1; echo AAAAAAAA | socat - 'udp-connect:[::1]:36563' ) &
pids+=" $!"
sleep 2
) 2>/dev/null | grep AAAAAAAA >/dev/null; then
    echo "Test succeeded."
else
    echo "Test failed."
    exit 1
fi
