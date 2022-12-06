#!/bin/bash

# sudo dmesg --clear   # 显示开机信息
sudo insmod lightmac.ko len=64   #insmod 直接编译进内核
# dmesg
sudo rmmod lightmac  # 删除这个模块


# sudo dmesg --clear
# sudo insmod lightmac.ko  len=128
# dmesg
# sudo rmmod lightmac

# sudo dmesg --clear
# sudo insmod lightmac.ko  
# dmesg
# sudo rmmod lightmac

# sudo dmesg --clear
# sudo insmod lightmac.ko  len=320
# dmesg
# sudo rmmod lightmac

# sudo dmesg --clear
# sudo insmod lightmac.ko  len=384
# dmesg
# sudo rmmod lightmac