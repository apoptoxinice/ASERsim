#!/bin/bash
echo $#
if [ $# != 1 ] ; then
  echo "USAGE: $0 filename"
  echo "e.g. $0 ospf6_message.c"
  exit 1;
fi

echo $1
#scp $1 root@[fd16:e20e:938::653]:/root/workspace/qpim-0.99.23/
scp $1 root@[fd16:e20e:938:0:8ef5:8096:2f22:df7c]:/root/workspace/qpim-0.99.23/
