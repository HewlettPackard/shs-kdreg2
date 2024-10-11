#!/bin/bash
#
# Run kdreg2 tests

dir=$(realpath $(dirname $0))
source $dir/env.sh

TEST_DIR=$TOP_DIR/tests

#build the tests
make -C $TEST_DIR tests
err=$?
if [[ $err -ne 0 ]]
then
    exit $err
fi

#the Makefile can tell us all the tests to execute
tests=$(make -C $TEST_DIR --silent --no-print-directory echo_tests)
err=$?

if [[ $err -ne 0 ]] || [[ -z $tests ]]
then
    echo "Unable to get list of tests to execute: $err"
    echo "$0 exiting with $err"
    exit $err
fi

for t in $tests
do
    $TEST_DIR/$t
    err=$?
    if [[ $err -ne 0 ]]
    then
	break
    fi
done

exit $err

