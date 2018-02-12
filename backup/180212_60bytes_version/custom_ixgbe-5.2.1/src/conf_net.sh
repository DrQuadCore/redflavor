#!/bin/bash

echo "sudo rmmod ixgbe"
sudo rmmod ixgbe
sleep 0.5 
echo "sudo insmod ixgbe.ko"
sudo insmod ixgbe.ko
sleep 0.5 
echo "sudo ifconfig eth3 10.0.0.2 netmask 255.255.255.0"
sudo ifconfig eth3 10.0.0.2 netmask 255.255.255.0
echo "sudo route add -net 10.0.0.0 netmask 255.255.255.0 dev eth3"
sudo route add -net 10.0.0.0 netmask 255.255.255.0 dev eth3
