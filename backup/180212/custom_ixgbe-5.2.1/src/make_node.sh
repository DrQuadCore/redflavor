#!/bin/bash
grep ixgbe /proc/devices >/dev/null
# create device inodes
major=`fgrep ixgbe /proc/devices | cut -b 1-4`
echo "INFO: driver major is $major"

# remove old inodes just in case
if [ -e /dev/ixgbe ]; then
    sudo rm /dev/ixgbe
fi

echo "INFO: creating /dev/ixgbe inode"
sudo mknod /dev/ixgbe c $major 0
sudo chmod a+w+r /dev/ixgbe
