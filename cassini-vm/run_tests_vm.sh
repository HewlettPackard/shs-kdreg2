#!/bin/bash
#
# Run unit tests in a VM.

dir=$(dirname $0)
source $dir/env.sh

RUNCMD=${SCRIPT_DIR}/test.sh

if ! [ -c /dev/cxi0 ]; then
	echo "Cassini device not present; attempting to launch netsim VM"
	RUNCMD="$RUNCMD" ${SCRIPT_DIR}/startvm.sh
else
	${RUNCMD}
fi

err=$?
echo "$0 exiting with $err"

exit $?
