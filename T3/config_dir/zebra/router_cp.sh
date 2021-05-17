#/bin/sh

router_eth0=$(ifconfig | awk '/eth0/{print $1}')
echo $router_eth0

router_eth1=$(ifconfig | awk '/eth1/{print $1}')
echo $router_eth1


router=${router_eth0%-eth0}
echo $router

file_name=zebra_$router.conf
echo $file_name

id=${router:1}
echo $id

cp ./zebra_r0.conf ./zebra_$router.conf

sed -i "s/interface r0-eth0/interface $router_eth0/g" $file_name
sed -i "s/interface r0-eth1/interface $router_eth1/g" $file_name
sed -i "s#ipv6 address 2001:3:0:1::1/64#ipv6 address 2001:3:$id:1::1/64#g" $file_name
sed -i "s#ipv6 address 2001:3:0:2::1/64#ipv6 address 2001:3:$id:2::1/64#g" $file_name
#sed -i "s/ipv6 ospf6 priority 0/ipv6 ospf6 priority $id/g" $file_name
#sed -i "s/router-id 0.0.0.0/router-id $id.$id.$id.$id/g" $file_name
#sed -i "s/router-id 0.0.0.0/router-id $id.$id.$id.$id/g" $file_name


