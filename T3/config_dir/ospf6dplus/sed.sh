sed -i '12d' ./ospf6dplus_r*
sed -i '12 s/^/debug ospf6 interface\n/' ./ospf6dplus_r* 
sed -i '13 s/^/debug ospf6 neighbor\n/' ./ospf6dplus_r*
sed -i '14 s/^/debug ospf6 route table\n/' ./ospf6dplus_r*
#debug ospf6 neighbor
#debug ospf6 route table

