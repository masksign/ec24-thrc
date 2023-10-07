#!/bin/bash

#	Disable frequency scaling until the next boot. Intel:
#		echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo
#	AMD:
#		echo 0 > /sys/devices/system/cpu/cpufreq/boost

for n in 0002 0004 0008 0016 0032 0064 0128 0256 0512 1024
do
	time ./xtest $n $n $n | tee dat/u2-$n.txt
done

