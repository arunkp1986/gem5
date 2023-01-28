#!/bin/bash

outdir=$1
bench=$2

if [[ -f "PhyMem.0" ]];then
rm PhyMem.0
fi
if [[ -f "PhyMem.1" ]];then
rm PhyMem.1
fi

./build/X86/gem5.opt --outdir=$outdir configs/spec_config/run_spec.py "/home/kparun/stack_persistence/gem5/fullsystem_images/vmlinux-v5.2.3" "/home/kparun/hybrid_work/spec-2017-image/spec-2017" "timing" "$bench" "test"

