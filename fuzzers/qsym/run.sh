#!/bin/bash

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
# - env TARGET: path to target work dir
# - env OUT: path to directory where artifacts are stored
# - env SHARED: path to directory shared with host (to store results)
# - env PROGRAM: name of program to run (should be found in $OUT)
# - env ARGS: extra arguments to pass to the program
# - env FUZZARGS: extra arguments to pass to the fuzzer
##

mkdir -p "$SHARED/findings"

export AFL_SKIP_CPUFREQ=1
export AFL_NO_AFFINITY=1
cd $OUT

# ignore two comments bellow. They are for driller.
#shellphuzz --memory 100M -s "$TARGET/corpus/$PROGRAM" -w "$SHARED/findings" \
#    "$OUT/$PROGRAM"  2>&1


# run AFL master
$AFL_ROOT/afl-fuzz -M afl-master -i "$TARGET/corpus/$PROGRAM" -o "$OUT/$PROGRAM" -- $AFL_CMDLINE
# run AFL slave
$AFL_ROOT/afl-fuzz -S afl-slave -i "$TARGET/corpus/$PROGRAM" -o "$OUT/$PROGRAM" -- $AFL_CMDLINE
# run QSYM
bin/run_qsym_afl.py -a afl-slave -o "$TARGET/corpus/$PROGRAM" -n qsym -- $QSYM_CMDLINE
