#!/bin/bash

echo "sudo rmmod ixgbe"
sudo rmmod ixgbe
sleep 1
echo "sudo insmod ixgbe.ko"
sudo insmod ixgbe.ko
sleep 1
echo "sudo ifconfig enp2s0f1 1.1.1.11 netmask 255.255.255.0"
sudo ifconfig enp2s0f1 1.1.1.11 netmask 255.255.255.0
echo "sudo route add -net 1.1.1.0 netmask 255.255.255.0 gw 1.1.1.1 dev enp2s0f1"
sudo route add -net 1.1.1.0 netmask 255.255.255.0 gw 1.1.1.1 dev enp2s0f1
