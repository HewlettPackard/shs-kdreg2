#!/bin/bash

dir=$(dirname $0)
prog=$(realpath $dir/test_threads)
num=16

echo "****************************************************"
echo "Launching ${num} instances of ${prog} in parallel..."
echo "****************************************************"

pids=""
for i in $(seq 1 $num); do
    $prog &
    pid=$!
    echo "Instance $i pid $pid"
    pids+=" $pid"
done

failures=0
for p in $pids; do
    if wait $p; then
	echo "Pid $p success"
    else
	echo "Pid $p failure"
	((++failures))
    fi
done

echo "********************************"
if [[ $failures -gt 0 ]]; then
    echo "Test $BASH_SOURCE fails"
    exit $failures
else
    echo "Test $BASH_SOURCE succeeds"
fi
echo "********************************"
