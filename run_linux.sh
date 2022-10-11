#!/bin/bash

#outdir=$1
bench=$1
cwd=$(pwd)

if [[ -f "PhyMem.0" ]];then
rm PhyMem.0
fi
if [[ -f "PhyMem.1" ]];then
rm PhyMem.1
fi

./build/X86/gem5.opt --outdir=$cwd"/m5out" configs/spec_config/run_spec.py $cwd"/fullsystem_images/vmlinux-v5.2.3" $cwd"/fullsystem_images/spec-2017-image/spec-2017" "timing" "$bench" "test"

