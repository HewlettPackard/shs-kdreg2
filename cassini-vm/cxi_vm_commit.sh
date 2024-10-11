#!/bin/bash

dir=$(dirname $0)
source $dir/env.sh

make -C $TOP_DIR clean
make -C $TOP_DIR -j modules tests

# We need a TTY, otherwise the tests will not finish. So ssh to self.

ssh -tt localhost <<EOF
cd $TOP_DIR; $SCRIPT_DIR/run_tests_vm.sh; exit \$?
EOF

err=$?
echo "$0 exiting with $err"

exit $err
