#!/bin/bash
#stop crond for watchquagga
service  crond stop
#kill watchquagga
killall watchquagga
#kill zebra,ospf6d,bgpd
killall zebra
killall ospf6d
killall bgpd
#make install zebra,ospf6d,bgpd
make install
#start crond
service crond start
