#!/bin/bash

cat write_time | awk '{sum += $1; cols += 1} END {print "write time: " sum / (NR*1000000)}'
cat read_time | awk '{sum += $1; cols += 1} END {print "read time: " sum / (NR*1000000)}'
cat classify_time | awk '{sum += $1; cols += 1} END {print "classify time: " sum / (NR*1000000)}'
cat log_time | awk '{sum += $1; cols += 1} END {print "log time: " sum / (NR*1000000)}'

