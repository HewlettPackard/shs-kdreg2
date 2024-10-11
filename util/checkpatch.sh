#!/bin/bash

script_dir=$(realpath $(dirname ${BASH_SOURCE[0]}))
check=$(realpath $script_dir/../contrib/checkpatch.pl)

ignore="SYMBOLIC_PERMS,SPLIT_STRING,LINUX_VERSION_CODE,PREFER_PACKED,CONST_STRUCT"

$check --no-tree --max-line-length=85 --ignore "$ignore" -f $@
