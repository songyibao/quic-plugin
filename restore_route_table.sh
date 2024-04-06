# 删除向interface1表添加的默认路由
ip route del default via 10.142.0.1 dev enp6s0 table interface1

# 删除向interface2表添加的默认路由
ip route del default via 172.20.10.1 dev wlo1 table interface2

# 删除添加的规则
ip rule del from 10.142.7.11 table interface1
ip rule del from 172.20.10.3 table interface2
