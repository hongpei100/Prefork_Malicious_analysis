#!/bin/bash

cat write_time | awk '{sum += $1; cols += 1} END {print sum / (NR*100000)}'
cat read_time | awk '{sum += $1; cols += 1} END {print sum / (NR*100000)}'
cat classify_time | awk '{sum += $1; cols += 1} END {print sum / (NR*100000)}'
cat log_time | awk '{sum += $1; cols += 1} END {print sum / (NR*100000)}'

