#!/bin/bash

#set -x

echo "Setting up env vars..."

if [[ -z $SCRIPT_DIR ]]; then
    SCRIPT_DIR=$(realpath `dirname $0`)
fi

if [[ -z $TOP_DIR ]]; then
    TOP_DIR=$(realpath $SCRIPT_DIR/..)
fi

if [[ -z $DBS_DIR ]]; then
    DBS_DIR=$(realpath $TOP_DIR/../)
fi

ENVS="DBS_DIR SCRIPT_DIR TOP_DIR"

export DBS_DIR=$DBS_DIR
export SCRIPT_DIR=$SCRIPT_DIR
export TOP_DIR=$TOP_DIR

for v in $ENVS
do
    echo "$v=`printenv $v`"
done

for v in $ENVS
do
    if [[ -z ${!v} ]]; then
	echo "Unable to determine $v, exiting."
	exit 1
    fi
done

echo "Env vars setup done..."
