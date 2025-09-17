#!/bin/sh

# Get absolute directory of this script
dir="$(cd "$(dirname "$0")" && pwd)"
source $dir/env.sh

insmod $TOP_DIR/kdreg2.ko

exec bash --rcfile <(echo 'echo "Interactive shell started in VM"') -i

err=$?

echo "$0 exiting with $err"

exit $err
