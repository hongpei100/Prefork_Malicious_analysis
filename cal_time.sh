#!/bin/bash

cat write_time* | awk '{sum += $1;} END {print sum / (NR*1000000)}'
cat read_time* | awk '{sum += $1;} END {print sum / (NR*1000000)}'
cat classify_time* | awk '{sum += $1;} END {print sum / (NR*1000000)}'
cat log_time* | awk '{sum += $1;} END {print sum / (NR*1000000)}'

