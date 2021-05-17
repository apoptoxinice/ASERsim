router_eth0=$(ifconfig | awk '/eth0/{print $1}')
#echo $router_eth0

router=${router_eth0%-eth0}
#echo $router

if [[ -z $router ]];then
    echo "not router"
    exit 0
fi
echo "is router"

file_name=ospf6d_$router.conf
#echo $file_name

id=${router:1}
#echo $id

t=$?
#echo $t

if [ $t -ne 0 ];then
    echo "not router"
    exit 0
fi


#if_num=`ip addr list |grep $router | wc -l`
if_num=`ip addr list |grep eth | wc -l`
let if_num=$if_num-1

for i in $(seq 1 $if_num)
do
#	echo $i
#:<<!
#if_name=`ip link | grep ^[0-9] | grep eth | awk -F: '{print $2}' |sed -n "$i,1p" `
if_name=`ip link  | grep eth |grep $router| awk -F: '{print $2}' |sed -n "$i,1p" `

if_vlan=`ip link  | grep $if_name |wc -l`

	#echo $if_name
	if_len=${#if_name}
	echo $if_len
	#echo $if_vlan
	#echo ${if_name%@*}
#!

#if [ $if_vlan -eq 1 ];then
if [ $if_len -ge 15 ];then
	#echo "vlan_num".$if_vlan
	#echo $if_name
	echo ${if_name%@*}
	tc qdisc add dev ${if_name%@*} root netem delay 250ms loss 10%
	#tc qdisc add dev ${if_name%@*} root netem loss 10%
	tc -s qdisc show dev ${if_name%@*}
fi



#tc qdisc add dev $if_name root netem delay 250ms
#tc qdisc add dev $if_name root netem loss 10%
#tc -s qdisc show dev $if_name

done

