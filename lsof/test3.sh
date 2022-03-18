#!/bin/bash

if [ -n "$1" ]; then
    your_program=$1;
else
    your_program="./ans_hw1";
fi

diff -uw <( /home/bowei/workspace/Unix-Programming/lsof/hw1.o -f dev) <(bash -c "/home/bowei/workspace/Unix-Programming/lsof/hw1.o -f dev") | egrep -v '^.testcase' | tee /home/bowei/workspace/Unix-Programming/lsof/testcase1_diff%
