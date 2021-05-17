#/bin/sh

#echo "123" >> /root/T1/crontab/1.txt

router_eth0=$(ifconfig | awk '/eth0/{print $1}')
echo $router_eth0

router=${router_eth0%-eth0}
echo $router

if [[ -z $router ]];then
    echo "not router"
    exit 0
fi
echo "is router"

id=${router:1}
echo $id


/root/T3/up_down/timer_1 $router $id



