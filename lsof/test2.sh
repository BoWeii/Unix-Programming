#!/bin/bash

your_program="/home/bowei/workspace/Unix-Programming/lsof/hw1.o";


ping -c 10 localhost >/dev/null 2>&1 &
P0=$!
nc -lu localhost 12345 >/dev/null 2>&1 &
P1=$!
nc -l localhost 23456 >/dev/null 2>&1 &
P2=$!

diff -uw <(/home/bowei/workspace/Unix-Programming/lsof/hw1.o -t SOCK) <(bash -c "$your_program -t SOCK") | egrep -v '^.testcase' | tee /tmp/testcase1_diff

kill -9 $P0 $P1 $P2%