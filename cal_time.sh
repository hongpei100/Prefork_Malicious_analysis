#!/bin/bash

cat write_time* | awk '{sum += $1;} END {print "Write time: " sum / (NR*1000000) " ms"}'
cat read_time* | awk '{sum += $1;} END {print "Read time: "sum / (NR*1000000) " ms"}'
cat classify_time* | awk '{sum += $1;} END {print "Classify time: "sum / (NR*1000000) " ms"}'
cat log_time* | awk '{sum += $1;} END {print "log time: "sum / (NR*1000000) " ms"}'

