#!/bin/bash

sudo apt install auditd
make
chmod +x quick_run.sh
sed -i -e 's/\r$//' quick_run.sh  
# -i 表示将修改保存到文件中, 否则只是将修改后的内容输出到终端，文件里面的内容不变
# -e 表示可以执行多个子命令