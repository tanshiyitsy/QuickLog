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
sudo insmod quickmod.ko  len=256
dmesg
sudo rmmod quickmod

sudo dmesg --clear
sudo insmod quickmod.ko  len=1024
dmesg
sudo rmmod quickmod

sudo dmesg --clear
sudo insmod quickmod.ko  len=2048
dmesg
sudo rmmod quickmod