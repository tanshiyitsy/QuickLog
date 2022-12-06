#!/bin/bash

sudo dmesg --clear
echo "start insmod"
sudo insmod quickmod.ko len=64
echo "end insmod"
dmesg
echo "end dmesg"
sudo rmmod quickmod
echo "end rmmod"


# sudo dmesg --clear
# sudo insmod quickmod.ko  len=128
# dmesg
# sudo rmmod quickmod

# sudo dmesg --clear
# sudo insmod quickmod.ko  
# dmesg
# sudo rmmod quickmod

# sudo dmesg --clear
# sudo insmod quickmod.ko  len=320
# dmesg
# sudo rmmod quickmod

# sudo dmesg --clear
# sudo insmod quickmod.ko  len=384
# dmesg
# sudo rmmod quickmod