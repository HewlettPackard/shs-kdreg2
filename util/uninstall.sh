#!/bin/bash
module="kdreg2"

exists=$(sudo lsmod | grep ${module})
if [ -z "${exists}" ] ; then
	echo "Module ${module} not found."
	exit 2
fi

sudo rmmod ${module}
exit $?
