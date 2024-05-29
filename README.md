# ebpf-sk-fastpath

## Prerequisites

1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Build Userspace

```bash
cargo build
```

## Build eBPF and Userspace

```bash
cargo xtask build
```

## Run

to use the unified cgroup, run the following command if `/sys/fs/cgroup/unified` doesn't exist

```bash
# mkdir /sys/fs/cgroup/unified
mount -t cgroup2 -o nsdelegate none /sys/fs/cgroup/unified
```

```bash
RUST_LOG=info cargo xtask run
```

and on another terminal, run `curl 127.0.0.1:your_port`
and on the third terminal, verify the program by `bpftrace bpftrace -e 'kprobe:tcp_bpf_update_proto { printf("%s: %d\n", comm, pid); }'`


## How it works 

when we insert a sk into the sock_map, `sock_map_link` is invoked in kernel, and will update the tcp/udp's operations will be replaced by `tcp_bpf_update_proto`, e.g. the `tcp_sendmsg` will be replaced by ``, ...

during the establishment of tcp connection, the sock_map will be updated twice, since there are two socket associated with this connection, the client with pair of (src, dst) and server with pair of (dst, src)

in the `tcp_bpf_sendmsg`, the bpf program of `sk_msg` will be called. in the program, we can use `bpf_msg_redirect_hash` helper function to redirect the sending sk to the socket that has also been stored in the sock_map