#!/bin/bash

outdir=$1
gemoskernel=$2

if [[ -f "PhyMem.0" ]];then
rm PhyMem.0
fi
if [[ -f "PhyMem.1" ]];then
rm PhyMem.1
fi

./build/X86/gem5.opt --outdir=$outdir configs/example/fs.py --mem-size=3GB --nvm-size=2GB --caches --l3cache --cpu-type TimingSimpleCPU --hybrid-channel True --mem-type=DDR4_2400_16x4 --nvm-type=NVM_2666_1x64 --kernel=$gemoskernel  --disk-image /home/kparun/stack_persistence/gem5/fullsystem_images/gemos.img

