#/bin/sh


router_eth0=$(ifconfig | awk '/eth0/{print $1}')
echo $router_eth0



router=${router_eth0%-eth0}
echo $router

if [[ -z $router ]];then
    echo "not router"
    exit 0
fi
echo "is router"

file_name=ospf6d_$router.conf
echo $file_name

id=${router:1}
echo $id

t=$?
echo $t

if [ $t -ne 0 ];then
    echo "not router"
    exit 0
fi

cd /root/T3/
./vlan.sh $id


#exit 0
:<<!
cd /root/T3/config_dir/ospf6d
./router_cp.sh


cd /root/T3/config_dir/ospf6dplus
./router_cp.sh

cd /root/T3/config_dir/zebra
./router_cp.sh

cd /root/T3/config_dir/bgpd
./router_cp.sh

cd /root/T3/config_dir/gdb
./router_cp.sh
!


#:<<!
cd /root/T3/program_dir/ospf6d
cp ./ospf6d ./ospf6d_$router -f

cd /root/T3/program_dir/ospf6dplus
cp ./ospf6d ./ospf6dplus_$router -f

cd /root/T3/program_dir/zebra
cp ./zebra ./zebra_$router -f

cd /root/T3/program_dir/bgpd
cp ./bgpd ./bgpd_$router -f
#!

#:<<!
let zebra_p=3000+id
echo $zebra_p
/root/T3/program_dir/zebra/zebra_$router -d -f /root/T3/config_dir/zebra/zebra_$router.conf -i /var/run/zebra_$router.pid -z /var/run/zserv_$router.api -P $zebra_p

sleep 5

let ospf6d_p=4000+id
echo $ospf6d_p
/root/T3/program_dir/ospf6d/ospf6d_$router -d -f /root/T3/config_dir/ospf6d/ospf6d_$router.conf -i /var/run/ospf6d_$router.pid -z /var/run/zserv_$router.api -P $ospf6d_p

let ospf6dplus_p=5000+id
echo $ospf6dplus_p
#/root/T3/program_dir/ospf6dplus/ospf6dplus_$router -d -f /root/T3/config_dir/ospf6dplus/ospf6dplus_$router.conf -i /var/run/ospf6dplus_$router.pid -z /var/run/zserv_$router.api -P $ospf6dplus_p

gdb --args /root/T3/program_dir/ospf6dplus/ospf6dplus_$router -f /root/T3/config_dir/ospf6dplus/ospf6dplus_$router.conf -i /var/run/ospf6dplus_$router.pid -z /var/run/zserv_$router.api -P $ospf6dplus_p 0</root/T3/config_dir/gdb/gdb_cmd_$router.txt &



#!
:<<!
let bgpd_p=6000+id
echo $bgpd_p
/root/T3/program_dir/bgpd/bgpd_$router -d -f /root/T3/config_dir/bgpd/bgpd_$router.conf -i /var/run/bgpd_$router.pid -z /var/run/zserv_$router.api -P $bgpd_p
!

#/root/T3/tc.sh

exit 0
cd /root/T3/up_down
./test.sh
