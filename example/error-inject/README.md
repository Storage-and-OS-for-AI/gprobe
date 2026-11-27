# error-inject

gprobe can allow you override the execution of a function in userspace, and return a value you specify, or error injection in the system call.

It's useful for testing the error handling of your program.

## Run for override userspace function

server

```sh
LD_PRELOAD=~/.gprobe/libgprobe-syscall-server.so ./error_inject
```

client

```sh
LD_PRELOAD=~/.gprobe/libgprobe-agent.so ./victim
```
