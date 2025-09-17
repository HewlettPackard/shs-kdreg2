#!/bin/bash

# Wrapper script to run startvm.sh in standalone mode

dir=$(dirname $0)

# Call startvm.sh with the --standalone parameter and pass through any other arguments
"$dir/startvm.sh" --standalone "$@"

err=$?

echo "$0 exiting with $err"

exit $err
