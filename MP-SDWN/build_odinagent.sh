#!/bin/sh

ifconfig wlan0 up

#make sure your ap openvswitch is start.if not,start manully
echo "openvswitch start..."
/etc/init.d/openvswitch start
echo "openvswitch end..."

#clean env
ovs-vsctl del-br br0
#delete the old bridge
ifconfig br-lan down
brctl delbr br-lan

#instantiate OpenvSwitch
ovs-vsctl add-br br0
#ovs-vsctl add-br br1
ifconfig br0 172.24.4.31 netmask 255.255.255.0 up
#route add default gw 192.168.1.1
ovs-vsctl set-controller br0 tcp:172.24.4.195:6633
ovs-vsctl add-port br0 eth0.1
ovs-vsctl add-port br0 wlan0
#ovs-vsctl del-port br0 ap


#vbridge stat(br0)
echo "------ovs-vsctl show--------------"
ovs-vsctl show

#vbridge iface stat
echo "------ovs-ofctl show br0--------------"
ovs-ofctl show br0

#vbridge flow stat(not include hidden flows)
echo "------ovs-ofctl dump-flows br0--------------"
ovs-ofctl dump-flows br0

#start wiagent
wiagent 172.24.4.195 
