ip route add default via 10.142.0.1 dev enp6s0 table interface1
ip route show table interface1
ip route add default via 172.20.10.1 dev wlo1 table interface2
ip route show table interface2
ip rule add from 10.142.7.11 table interface1
ip rule add from 172.20.10.3 table interface2
ip rule