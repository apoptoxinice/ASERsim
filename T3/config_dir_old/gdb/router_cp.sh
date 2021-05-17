#/bin/sh

router_eth0=$(ifconfig | awk '/eth0/{print $1}')
echo $router_eth0

router_eth1=$(ifconfig | awk '/eth1/{print $1}')
echo $router_eth1


router=${router_eth0%-eth0}
echo $router

file_name=gdb_cmd_$router.txt
echo $file_name

id=${router:1}
echo $id

cp ./gdb_cmd_r0.txt ./gdb_cmd_$router.txt

sed -i "s/debug_r0.txt/debug_$router.txt/g" $file_name
