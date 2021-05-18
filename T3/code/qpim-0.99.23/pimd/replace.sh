#!/bin/bash
#sed -i "s/\<1struct pimsm_prefix_ipv4_list\>/struct pimsm_prefix_ipv6_list/g" `grep '\<1struct pimsm_prefix_ipv4_list\>' -rl *`

#sed -i "s/\<1VOS_IP_ADDR\>/VOS_IPV6_ADDR/g" `grep '\<1VOS_IP_ADDR\>' -rl *`

#sed -i "s/\<1ADDRF_IPv4\>/ADDRF_IPV6/g" `grep '\<1ADDRF_IPv4\>' -rl *`
#sed -i "s/\<1ADDRT_IPv4\>/ADDRT_IPV6/g" `grep '\<1ADDRT_IPv4\>' -rl *`
#sed -i "s/\<ADDRT_IPV6\>/ADDRT_IPV6/g" `grep '\<ADDRT_IPV6\>' -rl *`
#sed -i "s/\<1out_if\>/oil/g" `grep '\<1out_if\>' -rl *`
#sed -i "s/\<1in_ifindex\>/iif/g" `grep '\<1in_ifindex\>' -rl *`
sed -i "s/\<iif\>/iif/g" `grep '\<iif\>' -rl *`
