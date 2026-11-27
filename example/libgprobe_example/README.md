# Example program

This is a sample program showcasing the use of libgprobe.

I am using headers from runtime and I am linking `libgprobe.a` which is installed in `~/.gprobe`

## Prerequisites

following command should have been run, so that `libgprobe.a` exists in `~/.gprobe` directory

```shell
cmake -Bbuild  -DCMAKE_BUILD_TYPE:STRING=Release \
           -DSPDLOG_ACTIVE_LEVEL=SPDLOG_LEVEL_INFO -DGPROBE_BUILD_STATIC_LIB=ON
cmake --build build --config Release --target install
```

## Build

- Makefile

You can make examples using makefile:

> Using make to run examples is preferred

run `make` and you will see the following output

```shell
Available targets:
 shm_example          build shared memory example
 clean                clean the build
```

command to execute the code:
when not using llvm-jit

```shell
g++ -o example main.cpp -I../../runtime/include -I../../vm/compat/include/ -I../../third_party/spdlog/include -I../../vm/vm-core/include -L~/.gprobe -lgprobe -lboost_system -lrt -lbpf
```
