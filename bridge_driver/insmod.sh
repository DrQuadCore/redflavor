#!/bin/bash
# Copyright (c) 2014, NVIDIA CORPORATION. All rights reserved.
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in 
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

THIS_DIR=$(dirname $0)

# remove driver
grep mydrv /proc/devices >/dev/null && sudo /sbin/rmmod mydrv

# insert driver
sudo /sbin/insmod mydrv/mydrv.ko dbg_enabled=1 info_enabled=1

# create device inodes
major=`fgrep mydrv /proc/devices | cut -b 1-4`
echo "INFO: driver major is $major"

# remove old inodes just in case
if [ -e /dev/mydrv ]; then
    sudo rm /dev/mydrv
fi

echo "INFO: creating /dev/mydrv inode"
sudo mknod /dev/mydrv c $major 0
sudo chmod a+w+r /dev/mydrv
