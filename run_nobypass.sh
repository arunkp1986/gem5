#!/bin/bash

outdir=$1

if [[ $# -ne 1 ]];then
    echo "pass output dir"
    exit 2
fi

rm PhyMem.0
rm PhyMem.1

./build/X86/gem5.opt --outdir=$outdir configs/example/fs.py --mem-size=3GB --nvm-size=2GB --caches --l3cache --cpu-type TimingSimpleCPU --hybrid-channel True --mem-type=DDR4_2400_16x4 --nvm-type=NVM_2666_1x64 --kernel /home/cse/arunkp/stack_persistence/gemOS_nvm_prosper_ssp/gemOS.kernel --disk-image /home/cse/arunkp/stack_persistence/gem5/fullsystem_images/data_gapbs.img

