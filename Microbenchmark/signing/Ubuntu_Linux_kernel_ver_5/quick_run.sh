#!/bin/bash

sudo dmesg --clear
sudo insmod quickmod.ko len=64
dmesg
sudo rmmod quickmod


sudo dmesg --clear
sudo insmod quickmod.ko  len=128
dmesg
sudo rmmod quickmod

sudo dmesg --clear
sudo insmod quickmod.ko  len=192
dmesg
sudo rmmod quickmod


sudo dmesg --clear
sudo insmod quickmod.ko  len=256
dmesg
sudo rmmod quickmod

sudo dmesg --clear
sudo insmod quickmod.ko  len=320
dmesg
sudo rmmod quickmod

sudo dmesg --clear
sudo insmod quickmod.ko  len=384
dmesg
sudo rmmod quickmod

sudo dmesg --clear
sudo insmod quickmod.ko  len=448
dmesg
sudo rmmod quickmod