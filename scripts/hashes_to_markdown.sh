#!/bin/bash

cat <<EOF
| Binary | Hash |
|-------|-------|
EOF
for hash_bin_name in `ls $1/*.hash`
do
  bin_name=`basename "$hash_bin_name" | sed 's/\.hash//'`
  echo "|$bin_name|`cat $hash_bin_name | awk '{print $1}'`|"
done