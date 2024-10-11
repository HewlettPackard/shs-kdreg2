#!/bin/bash

# set -x

dir=$(dirname $0)
prog=$(realpath $dir/test_fork3)

# test_fork3 will reverse the functionality of the
# the forked and main processes if any argument is passed

$prog "reversed"

exit $?
