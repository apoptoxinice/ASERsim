#!/bin/bash
#cd /root/software_install_for_dky/
#tar xzf qpim-0.99.23_20191213.tar.gz
#cd qpim-0.99.23
./configure --enable-vtysh --enable-zebra --enable-bgpd --enable-pimd  --enable-user=ice --enable-group=ice -enable-vty-group=ice
make;make install
#cp *.conf /usr/local/etc/
