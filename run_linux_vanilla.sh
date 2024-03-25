#!/bin/bash

if [ "$#" -ne 1 ]; then
	echo "pass outdir and bench name"
	exit 1
fi
outdir=$1

./build/X86/gem5.opt --outdir=$outdir configs/example/gem5_library/x86-ubuntu-run-with-kvm.py
