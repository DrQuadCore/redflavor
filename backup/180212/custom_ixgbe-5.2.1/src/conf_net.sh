#!/bin/bash

echo "sudo rmmod ixgbe"
sudo rmmod ixgbe
sleep 1
echo "sudo insmod ixgbe.ko"
sudo insmod ixgbe.ko
sleep 1
#echo "sudo ifconfig eth3 1.1.1.31 netmask 255.255.255.0"
#sudo ifconfig eth3 1.1.1.31 netmask 255.255.255.0
#echo "sudo route add -net 1.1.1.0 netmask 255.255.255.0 gw 1.1.1.1 dev eth3"
#sudo route add -net 1.1.1.0 netmask 255.255.255.0 gw 1.1.1.1 dev eth3
