#!/bin/bash
#sed -i "s/\<1PIMSM_ASSERT_METRIC_T\>/struct pimsm_assert_metric/g" `grep '\<1PIMSM_ASSERT_METRIC_T\>' -rl *`

#sed -i "s/\<1PIMSM_ASSERT_IF_T\>/struct pimsm_assert_if/g" `grep '\<1PIMSM_ASSERT_IF_T\>' -rl *`

#sed -i "s/\<1dwIfIndex\>/ifindex/g" `grep '\<1dwIfIndex\>' -rl *`

#sed -i "s/\<1stDestAddr\>/dest_addr/g" `grep '\<1stDestAddr\>' -rl *`

#sed -i "s/\<1stNextHopAddr\>/rpf_nbr_addr/g" `grep '\<1stNextHopAddr\>' -rl *`

#sed -i "s/\<1stRpAddr\>/rp_addr/g" `grep '\<1stRpAddr\>' -rl *`

#sed -i "s/\<1stUpstreamIf\>/upstream_if/g" `grep '\<1stUpstreamIf\>' -rl *`

#sed -i "s/\<1pstAssertIf\>/pimsmassert_if/g" `grep '\<1pstAssertIf\>' -rl *`
#sed -i "s/\<1dwPreference\>/preference/g" `grep '\<1dwPreference\>' -rl *`
#sed -i "s/\<1dwMetric\>/metric/g" `grep '\<1dwMetric\>' -rl *`
#sed -i "s/\<1byType\>/type/g" `grep '\<1byType\>' -rl *`
#sed -i "s/\<1pstGroup\>/group/g" `grep '\<1pstGroup\>' -rl *`
#sed -i "s/\<1stUpstreamNbrAddr\>/up_stream_nbr/g" `grep '\<1stUpstreamNbrAddr\>' -rl *`

#sed -i "s/\<1stOldUpstreamNbrAddr\>/old_upstream_nbr_addr/g" `grep '\<1stOldUpstreamNbrAddr\>' -rl *`
#sed -i "s/\<1stNewUpstreamNbrAddr\>/new_upstream_nbr_addr/g" `grep '\<1stNewUpstreamNbrAddr\>' -rl *`



##########3333
#sed -i "s/\<1dwOutCountHello\>/hello_send/g" `grep '\<1dwOutCountHello\>' -rl *`

#sed -i "s/\<1dwInCountHello\>/hello_recv/g" `grep '\<1dwInCountHello\>' -rl *`

#sed -i "s/\<1dwInCountJoinPrune\>/join_prune_recv/g" `grep '\<1dwInCountJoinPrune\>' -rl *`

#sed -i "s/\<1dwInCountBootstrap\>/bootstrap_recv/g" `grep '\<1dwInCountBootstrap\>' -rl *`

#sed -i "s/\<1dwInCountAssert\>/assert_recv/g" `grep '\<1dwInCountAssert\>' -rl *`

#sed -i "s/\<1dwInCountGraft\>/graft_recv/g" `grep '\<1dwInCountGraft\>' -rl *`

#sed -i "s/\<1dwOutCountJoinPrune\>/join_prune_send/g" `grep '\<1dwOutCountJoinPrune\>' -rl *`

#sed -i "s/\<1dwOutCountBootstrap\>/bootstrap_send/g" `grep '\<1dwOutCountBootstrap\>' -rl *`

#sed -i "s/\<1dwOutCountAssert\>/assert_send/g" `grep '\<1dwOutCountAssert\>' -rl *`

#sed -i "s/\<1dwOutCountGraft\>/graft_send/g" `grep '\<1dwOutCountGraft\>' -rl *`

#sed -i "s/\<1stStatInfo\>/pimsm_ifstat/g" `grep '\<1stStatInfo\>' -rl *`

#sed -i "s/\<1iRetval\>/ret/g" `grep '\<1iRetval\>' -rl *`

#sed -i "s/\<1pstNbrPrimaryAddr\>/nbr_primary_addr/g" `grep '\<1pstNbrPrimaryAddr\>' -rl *`

#sed -i "s/\<1stDstAddr\>/dst_addr/g" `grep '\<1stDstAddr\>' -rl *`

#sed -i "s/\<1stSrcAddr\>/src_addr/g" `grep '\<1stSrcAddr\>' -rl *`

#sed -i "s/\<1dwDataLen\>/data_len/g" `grep '\<1dwDataLen\>' -rl *`

#sed -i "s/\<1pimsm_IfUp\>/pimsm_zebra_if_state_up/g" `grep '\<1pimsm_IfUp\>' -rl *`

#sed -i "s/\<1bAddr\>/u8_addr/g" `grep '\<1bAddr\>' -rl *`

#sed -i "s/\<1wAddr\>/u16_addr/g" `grep '\<1wAddr\>' -rl *`

#sed -i "s/\<1dwAddr\>/u32_addr/g" `grep '\<1dwAddr\>' -rl *`

#sed -i "s/\<1stAddr\>/addr/g" `grep '\<1stAddr\>' -rl *`

#sed -i "s/\<1byAddrMaskLen\>/prefixlen/g" `grep '\<1byAddrMaskLen\>' -rl *`

#sed -i "s/\<1dwAddrType\>/addr_type/g" `grep '\<1dwAddrType\>' -rl *`

#sed -i "s/\<1iRecvLifNo\>/input_ifindex/g" `grep '\<1iRecvLifNo\>' -rl *`

#sed -i "s/\<1stGrpAddr\>/grp_addr/g" `grep '\<1stGrpAddr\>' -rl *`

#sed -i "s/\<1pstStarGrpEntry\>/start_grp_entry/g" `grep '\<1pstStarGrpEntry\>' -rl *`

#sed -i "s/\<1pstSrcGrpEntry\>/src_grp_entry/g" `grep '\<1pstSrcGrpEntry\>' -rl *`

#sed -i "s/\<1pstMrtEntry\>/mrt_entry/g" `grep '\<1pstMrtEntry\>' -rl *`

#sed -i "s/\<1stUpNbrAddr\>/up_nbr_addr/g" `grep '\<1stUpNbrAddr\>' -rl *`

#sed -i "s/\<1pstOil\>/oif/g" `grep '\<1pstOil\>' -rl *`

#sed -i "s/\<1stAddress\>/address/g" `grep '\<1stAddress\>' -rl *`


#sed -i "s/\<1pstSource\>/source/g" `grep '\<1pstSource\>' -rl *`
#sed -i "s/\<1pstGroup\>/group/g" `grep '\<1pstGroup\>' -rl *`


#sed -i "s/\<1stUpstreamIf\>/upstream_if/g" `grep '\<1stUpstreamIf\>' -rl *`

#sed -i "s/\<1pstDownstreamIf\>/downstream_if/g" `grep '\<1pstDownstreamIf\>' -rl *`

#sed -i "s/\<1byType\>/type/g" `grep '\<1byType\>' -rl *`

#sed -i "s/\<1dwFlags\>/flags/g" `grep '\<1dwFlags\>' -rl *`

#sed -i "s/\<1dwPacketMatchCount\>/packet_match_count/g" `grep '\<1dwPacketMatchCount\>' -rl *`

#sed -i "s/\<1pstAssertIf\>/pimsmassert_if/g" `grep '\<1pstAssertIf\>' -rl *`

#sed -i "s/\<1pstOlist\>/out_if/g" `grep '\<1pstOlist\>' -rl *`

#sed -i "s/\<1bValid\>/valid/g" `grep '\<1bValid\>' -rl *`

#sed -i "s/\<1dwInIfIndex\>/in_ifindex/g" `grep '\<1dwInIfIndex\>' -rl *`

#sed -i "s/\<1PIMSM_GRP_ENTRY_T\>/struct pimsm_grp_entry/g" `grep '\<1PIMSM_GRP_ENTRY_T\>' -rl *`

#sed -i "s/\<1pstHardListNew\>/hard_list_new/g" `grep '\<1pstHardListNew\>' -rl *`

#sed -i "s/\<1pstHardListOld\>/hard_list_old/g" `grep '\<1pstHardListOld\>' -rl *`

#sed -i "s/\<1pstOil_1\>/oil_1/g" `grep '\<1pstOil_1\>' -rl *`

#sed -i "s/\<1pstOil_2\>/oil_2/g" `grep '\<1pstOil_2\>' -rl *`

#sed -i "s/\<1PIMSM_MRT_HARDWARE_ENTRY_T\>/struct pimsm_mrt_hardware_entry/g" `grep '\<1PIMSM_MRT_HARDWARE_ENTRY_T\>' -rl *`

#sed -i "s/\<1byRpfCheckError\>/rpf_check_error/g" `grep '\<1byRpfCheckError\>' -rl *`

#sed -i "s/\<1PIM_REGISTER\>/struct pimsm_register/g" `grep '\<1PIM_REGISTER\>' -rl *`

#sed -i "s/\<1dwIpPackLen\>/packet_len/g" `grep '\<1dwIpPackLen\>' -rl *`

#sed -i "s/\<1PIM_COMMON_HEADER\>/struct pimsm_common_header/g" `grep '\<1PIM_COMMON_HEADER\>' -rl *`

#sed -i "s/\<1PIM_HELLO\>/struct pimsm_hello/g" `grep '\<1PIM_HELLO\>' -rl *`

#sed -i "s/\<1cData\>/data/g" `grep '\<1cData\>' -rl *`

#sed -i "s/\<1wType\>/type/g" `grep '\<1wType\>' -rl *`

#sed -i "s/\<1wValueLen\>/value_len/g" `grep '\<1wValueLen\>' -rl *`

#sed -i "s/\<1PIM_ENCODED_SRC_ADDR\>/struct pimsm_encoded_src_addr/g" `grep '\<1PIM_ENCODED_SRC_ADDR\>' -rl *`

#sed -i "s/\<1PIM_ENCODED_GRP_ADDR\>/struct pimsm_encoded_grp_addr/g" `grep '\<1PIM_ENCODED_GRP_ADDR\>' -rl *`

#sed -i "s/\<1PIM_ENCODED_UNICAST_ADDR\>/struct pimsm_encoded_unicast_addr/g" `grep '\<1PIM_ENCODED_UNICAST_ADDR\>' -rl *`

#sed -i "s/\<1ucFamily\>/family/g" `grep '\<1ucFamily\>' -rl *`

#sed -i "s/\<1ucType\>/encoding_type/g" `grep '\<1ucType\>' -rl *`

#sed -i "s/\<1ucFlags\>/flags/g" `grep '\<1ucFlags\>' -rl *`

#sed -i "s/\<1ucMaskLen\>/mask_len/g" `grep '\<1ucMaskLen\>' -rl *`

#sed -i "s/\<1pucPimMsg\>/pim_msg/g" `grep '\<1pucPimMsg\>' -rl *`

#sed -i "s/\<1dwMsgLen\>/pim_msg_size/g" `grep '\<1dwMsgLen\>' -rl *`

###no exe
######sed -i "s/\<1pstSrcAddr\>/src_addr/g" `grep '\<1pstSrcAddr\>' -rl *`
###################

#sed -i "s/\<1PIM_JP_HEADER\>/struct pimsm_jp_header/g" `grep '\<1PIM_JP_HEADER\>' -rl *`

#sed -i "s/\<1stEncodUpstreamNbr\>/encod_upstream_nbr/g" `grep '\<1stEncodUpstreamNbr\>' -rl *`

#sed -i "s/\<1ucRsrvd\>/reserved/g" `grep '\<1ucRsrvd\>' -rl *`

#sed -i "s/\<1ucNumGrps\>/num_groups/g" `grep '\<1ucNumGrps\>' -rl *`

#sed -i "s/\<1PIM_JP_GRP\>/struct pimsm_jp_grp/g" `grep '\<1PIM_JP_GRP\>' -rl *`

#sed -i "s/\<1PIM_ASSERT\>/struct pimsm_assert/g" `grep '\<1PIM_ASSERT\>' -rl *`

#sed -i "s/\<1PIM_REGISTER_STOP\>/struct pimsm_register_stop/g" `grep '\<1PIM_REGISTER_STOP\>' -rl *`

#sed -i "s/\<1m_RtMgtRpfToPimsm_t\>/struct rtmgt_to_pimsm/g" `grep '\<1m_RtMgtRpfToPimsm_t\>' -rl *`

#sed -i "s/\<1dwSource\>/prefix/g" `grep '\<1dwSource\>' -rl *`

#sed -i "s/\<1dwRpfNeighbor\>/rpf_nbr_addr/g" `grep '\<1dwRpfNeighbor\>' -rl *`

#sed -i "s/\<1dwIif\>/iif/g" `grep '\<1dwIif\>' -rl *`

#sed -i "s/\<1PIMSM_RPF_ENTRY_T\>/struct pimsm_rpf_entry/g" `grep '\<1PIMSM_RPF_ENTRY_T\>' -rl *`

####20190411
#sed -i "s/\<1iFlags\>/options/g" `grep '\<1iFlags\>' -rl *`
sed -i "s/\<options\>/options/g" `grep '\<options\>' -rl *`
