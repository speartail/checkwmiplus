#!/usr/bin/env bash

set -Eeuo pipefail

file=$1

rm -rf check* etc

tar xf $file
# rm $file

find etc -type f | xargs chmod 644

for f in * etc/* ; do
  test -f $f || continue
  sed -i -e 's/[ \t]*$//' $f
done
