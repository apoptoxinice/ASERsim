echo $1

T=3
T_num=6
dev_num=11

case $T in
    1)  offset=0
;;
    2)  let offset=$dev_num*4
;;
    3)  offset=0
;;
    4)  offset=$dev_num
;;
    5)  let offset=$dev_num*2
;;
    6)  let offset=$dev_num*3
;;
    *)  echo 'default'
;;
esac

echo $offset

if [ $1 -ge 1 ];then
	if [ $1 -le 11 ];then
		route_id=$1
		echo $route_id
#		let if_id=0+$1
#		let if_id2=10+$1
		if_id=1
		if_id2=1

		let vlan_id=$offset+$1
		let vlan_id2=$vlan_id+$dev_num

		echo $vlan_id
		echo $vlan_id2

		ip link add link r$route_id-eth2 name r$route_id-eth2.$if_id type vlan id $vlan_id
		ip link
		ip link set dev r$route_id-eth2.$if_id up

		ip link add link r$route_id-eth2 name r$route_id-eth3.$if_id2 type vlan id $vlan_id2
		ip link
		ip link set dev r$route_id-eth3.$if_id2 up

		
	fi
	exit 0
fi
exit 0


