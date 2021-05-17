#/bin/sh

host_eth0=$(ifconfig | awk '/eth0/{print $1}')
echo $host_eth0

host=${host_eth0%-eth0}
echo $host

file_name=ospf6d_$host.conf
echo $file_name

id=${host:1}
echo $id

cp ./ospf6d_h0.conf ./ospf6d_$host.conf

sed -i "s/interface h0-eth0/interface $host_eth0/g" $file_name
sed -i "s/! ipv6 ospf6 priority0/! ipv6 ospf6 priority$id/g" $file_name
sed -i "s/router-id 0.0.0.0/router-id $id.$id.$id.$id/g" $file_name
sed -i "s/router-id 0.0.0.0/router-id $id.$id.$id.$id/g" $file_name


