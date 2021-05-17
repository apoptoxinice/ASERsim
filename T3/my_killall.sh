ps -ef |grep ospf6d_h |awk '{print $2}'|xargs kill -9
ps -ef |grep ospf6dplus_h |awk '{print $2}'|xargs kill -9
ps -ef |grep zebra_h |awk '{print $2}'|xargs kill -9


ps -ef |grep ospf6d_r |awk '{print $2}'|xargs kill -9
ps -ef |grep ospf6dplus_r |awk '{print $2}'|xargs kill -9
ps -ef |grep zebra_r |awk '{print $2}'|xargs kill -9
ps -ef |grep bgpd_r |awk '{print $2}'|xargs kill -9
