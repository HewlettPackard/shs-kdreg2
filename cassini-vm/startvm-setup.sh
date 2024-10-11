#!/bin/sh
#
# Initialize a VM for kdreg2 testing and run a command.

dir=$(dirname $0)
source $dir/env.sh

if [[ -z $RUNCMD ]]; then
    RUNCMD="$@"
fi

export LC_ALL=en_US.UTF-8

insmod $TOP_DIR/kdreg2.ko

if [[ ! -z $RUNCMD ]]; then
    $RUNCMD
fi

err=$?
echo "$0 exiting with $err"

exit $err
