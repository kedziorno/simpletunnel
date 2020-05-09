#!/usr/bin/env bash
cgcreate -g memory:grp1
echo 200M > /sys/fs/cgroup/memory/grp1/memory.limit_in_bytes
echo 1G > /sys/fs/cgroup/memory/grp1/memory.memsw.limit_in_bytes
make
# server
#cgexec -g memory:grp1 sudo ./stream_descriptor -s -u
#cgexec -g memory:grp1 sudo ./stream_descriptor -s -t
# client
#cgexec -g memory:grp1 sudo ./stream_descriptor -c 10.137.0.15 -u
#cgexec -g memory:grp1 sudo ./stream_descriptor -c 10.137.0.15 -t

# todo maybe -w option ?
