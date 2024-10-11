#!/bin/bash

dir=$(dirname $0)
source $dir/env.sh

git checkout -b rebase-test-branch

# Build only first as it's fast

git rebase `git merge-base origin/main HEAD` --exec 'set -e; git log -1 && make clean && make -j4 modules'

# We need a TTY, otherwise the tests will not finish. So ssh to self.

ssh -tt localhost <<EOF
cd $TOP_DIR; $SCRIPT_DIR/run_tests_vm.sh; exit \$?
EOF

err=$?
echo "$0 exiting with $err"

exit $?
