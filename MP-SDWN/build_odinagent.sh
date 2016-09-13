#!/bin/sh

#prepare work
#make sure ap enable openvswitch in firmware
#make sure ap install click moudle in firmware

#create monitor mon0
ifconfig wlan0 down
iw phy phy0 interface add mon0 type monitor
iw dev wlan0 set channel 6 
ifconfig mon0 up
ifconfig mon0 mtu 1600
#ifconfig wlan0 up

#make sure your ap openvswitch is start.if not,start manully
echo "openvswitch start..."
/etc/init.d/openvswitch start
echo "openvswicht end..."

#clean env
ovs-vsctl del-br br0
#delete the old bridge
ifconfig br-lan down
brctl delbr br-lan

#instantiate OpenvSwitch
ovs-vsctl add-br br0
#ovs-vsctl add-br br1
ifconfig br0 172.23.22.5 netmask 255.255.255.0 up
#route add default gw 192.168.1.1
ovs-vsctl set-controller br0 tcp:172.23.22.90:6633
ovs-vsctl add-port br0 eth1.1
#ovs-vsctl del-port br0 ap


#instantiate fake ap
echo "click start begin..."
click-align agent.click | click &
#click-align agent.click.bak | click &
sleep 5
echo "click start end..."
ifconfig ap up
#ovs-vsctl add-port br1 ap
ovs-vsctl add-port br0 ap


#vbridge stat(br0)
echo "------ovs-vsctl show--------------"
ovs-vsctl show

#vbridge iface stat
echo "------ovs-ofctl show br0--------------"
ovs-ofctl show br0

#vbridge flow stat(not include hidden flows)
echo "------ovs-ofctl dump-flows br0--------------"
ovs-ofctl dump-flows br0
