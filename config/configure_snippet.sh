#! /bin/bash

# set -x

outfile=$1
variable=$2
values="$3"

snippet=snippets.o
include_file=snippets.h
err=-1

for setting in ${values}
do
	echo "#define ${variable} ${setting}" > ${include_file}
	rm -f ${snippet} ${outfile}
	make ${snippet} >& /dev/null
	err=$?
	if [[ ${err} -eq 0 ]]; then
		echo "#define ${variable} ${setting}" > ${outfile}
		rm -f ${include_file}
	    	break
	fi
done

exit ${err}
