#!/bin/bash
echo $#
if [ $# != 1 ] ; then
  echo "USAGE: $0 filename"
  echo "e.g. $0 ospf6_message.c"
  exit 1;
fi

echo $1
scp $1 root@[fd16:e20e:938::653]:/root/workspace/qpim-0.99.23/ospf6d/
