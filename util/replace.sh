#!/bin/bash

module="kdreg2"

exists=$(sudo lsmod | grep ${module})
if [ ! -z "${exists}" ] ; then
    sudo rmmod ${module}
    err=$?
    if [[ $err -ne 0 ]]; then
	exit $err
    fi
fi

sudo insmod ${module}.ko
err=$?
if [[ $err -ne 0 ]] ; then
	echo "insmod ${module}.ko failed: $err"
	echo $err
fi

exit $?
