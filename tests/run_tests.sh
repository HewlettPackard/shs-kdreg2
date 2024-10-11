#!/bin/bash
#
# Run kdreg2 tests

# set -x

TEST_DIR=$(realpath $(dirname $0))
TEST_RESULTS=$TEST_DIR/unit_tests.tap

tests=$(make -C $TEST_DIR --silent --no-print-directory echo_tests)
err=$?

if [[ $err -ne 0 ]] || [[ -z $tests ]]
then
    echo "Unable to get list of tests to execute: $err"
    echo "$0 exiting with $err"
    exit $err
fi

n=$(echo "$tests" | wc -w)
echo "Found $n tests to run: $tests"

echo "1..$n" > $TEST_RESULTS
i=0
num_errors=0
for t in $tests
do
    ((i+=1))
    echo "Running test $TEST_DIR/$t"
    $TEST_DIR/$t
    err=$?
    if [[ $err -ne 0 ]]
    then
	echo "not ok $i - $t $err" >> $TEST_RESULTS
	((num_errors+=1))
    else
	echo "ok $i - $t" >> $TEST_RESULTS
    fi
done

echo "$num_errors errors encountered while running $n unit tests."

echo "$(basename $0) exiting with $err"

exit $err
