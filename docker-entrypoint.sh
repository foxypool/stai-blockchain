#!/bin/bash
set -em

stai init
tail --retry --follow --lines=0 /root/.stai/*/log/debug.log &
stai run_daemon &
trap "stai stop all -d; exit 0" SIGINT SIGTERM
sleep 2
"$@"
fg
