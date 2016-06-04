#!/bin/bash

set -e

if [ -z "$INPUTFILE" ]; then
	echo "Must specify INPUTFILE" 1>&2
	exit 1
fi

if [ -z "$LEVEL" ]; then
	export LEVEL=50
fi

topdir="$(dirname "$0")/../.."
tmpfile="$(mktemp)"
trap "rm -f \"$tmpfile\"" EXIT

git checkout -f "$topdir/src/lzx_compress.c" > /dev/null

sed -i -e	\
"
    s/[0-9]\+ \* stats->num_observations/$BLOCK_CUTOFF * stats->num_observations/
    s/num_new_observations < [0-9]\+\>/num_new_observations < $OBSERVATIONS_PER_CHECK/
    s/\(#define[ \t]\+MIN_BLOCK_SIZE[ \t]\+\)[0-9]\+/\1$MIN_BLOCK_SIZE/
" "$topdir/src/lzx_compress.c"

make -C "$topdir" -j$(grep -c processor /proc/cpuinfo) > /dev/null

rm -f "$tmpfile"
"$topdir/wimlib-imagex" export "$INPUTFILE" all "$tmpfile" \
        --compress=lzx:$LEVEL --recompress > /dev/null

stat -c '%s' "$tmpfile"
