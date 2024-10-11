#!/bin/bash
module="kdreg2"

exists=$(sudo lsmod | grep ${module})
if [ ! -z "${exists}" ] ; then
	echo "Module ${module} already installed.  Unistall first."
	exit 2
fi

sudo insmod ${module}.ko
err=$?
if [[ $err -ne 0 ]] ; then
	echo "insmod ${module}.ko failed: $err"
	echo $err
fi

exit $?
