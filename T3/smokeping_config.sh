ip link add link rename4 name rename4.1 type vlan id 1
ip link
cat smokeping_config.sh 

ip addr add 2001:3:1:3::100/64 dev rename4.1
ip route add 2001::/16 via 2001:3:1:3::1 dev rename4.1
ovs-vsctl add-port s12 eth10
