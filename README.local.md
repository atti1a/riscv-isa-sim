How to run the `/build` version of the code:

```
$ export SPIKE_BUILD_DIR=$HOME/riscv-isa-sim/build
$ export LD_PRELOAD="$SPIKE_BUILD_DIR/libriscv.so $SPIKE_BUILD_DIR/libdummy_rocc.so $SPIKE_BUILD_DIR/libsoftfloat.so $SPIKE_BUILD_DIR/libspike_main.so"
$ ./spike pk hello
```
