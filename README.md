# ebpf-tproxy

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

bash```
# mkdir /sys/fs/cgroup/unified
mount -t cgroup2 -o nsdelegate none /sys/fs/cgroup/unified
```

```bash
RUST_LOG=info cargo xtask run
```
