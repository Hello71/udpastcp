#!/bin/sh
# this script tests basic udpastcp functionality.

: ${UDPASTCP:=./udpastcp}

test_bidi() {
    (
        pids=
        trap 'kill $pids' INT TERM EXIT
        $UDPASTCP client "$1" 36563 "$1" 64109 &
        pids="$!"
        $UDPASTCP server "$1" 64109 "$1" 41465 &
        pids="$pids $!"
        ( ( sleep 0.5; echo BBBBBBBB; ) | socat "udp-listen:41465,pf=${2}" - ) &
        pids="$pids $!"
        ( ( sleep 0.4; echo AAAAAAAA; ) | socat - "udp-connect:localhost:36563,pf=${2}" ) &
        pids="$pids $!"
        sleep 0.6
    )
}

nl='
'

if [ "$( test_bidi 127.0.0.1 ip4 )" = "AAAAAAAA${nl}BBBBBBBB" ]; then
    echo "IPv4 test succeeded."
else
    echo "IPv4 test failed."
    r=1
fi

if [ "$( test_bidi ::1 ip6 )" = "AAAAAAAA${nl}BBBBBBBB" ]; then
    echo "IPv6 test succeeded."
else
    echo "IPv6 test failed."
    r=1
fi

exit $r
