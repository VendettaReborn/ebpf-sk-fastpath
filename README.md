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

what we mainly do is to redirect the egress traffic of an interface, let's say wlo1, to an ingress of interface, let's say lo. So the traffic will go through the kernel's routing system `again`. And we can perform 2 hacks on this path:
1. mark the packet, so it will hit our defined `ip rule`, and pass it to the local process
2. assign the `skb->sk` with the tproxy's listnening sk.

with these two hacks, the kernel will know that the skb is handled by the tproxy listening socket, the very special one.

the first hacks can be done via setting the `mark` field of skb in the TC's bpf program, and the second can also be done there, with the magic of `bpf_sk_assign`.

The returning traffic from device lo should also be hacked, but it's quite the reversed path: the egress traffic of lo should be redirected to the ingress of wlo1.

So far, so good. But we can actually perform another optimization here: boost the sendmsg/recvmsg path.

The idea is that, the traffic between the proxied program and our tproxy program doesn't have to go through the entire network stack, it's more like a `IPC` mechanism, but in the form of socket's API. Luckily, kernel's developers provide a fastpath in such situations: `BPF_PROG_TYPE_SK_MSG` type of bpf programs.

the `SK_MSG` bpf program works with `BPF_MAP_TYPE_SOCKHASH`: when we insert a sk into the sock_map, `sock_map_link` is invoked in kernel, and the the tcp/udp's callbacks in its ops(`inet_stream_ops`) will be replaced by `tcp_bpf_update_proto`, e.g. the `tcp_sendmsg` will be replaced by `tcp_bpf_sendmsg`, the `tcp_recvmsg` will be replaced by `tcp_bpf_recvmsg` etc.

the question is, how do we know which sk to insert into the map? to do that, we can utilize another type of bpf programs: `BPF_PROG_TYPE_SOCK_OPS`. 

This type of bpf programs will be invoked whenever a socket's state is changed, for example, during the establishment of tcp connection, the active establishment(syn packet) and passive establishment(syn&ack packet) of the connection will trigger their events accordingly, and kernel will pass the event's op code and skb to the `SOCK_OPS` bpf program, in the program, what we do is to simply match the skb, record it into the `BPF_MAP_TYPE_SOCKHASH` that is shared between the `sk_ops` and `sk_msg` programs(so the proto will be updated, and the fastpath will be enabled)

back to the `SK_MSG` programs, we just need to reverse the 5-tuple, find the other side of the connection, and pass the skb to it via `bpf_msg_redirect_hash` helper function. the kernel will do the rest of the job in `tcp_bpf_sendmsg` and `tcp_bpf_recvmsg`.

```txt
Tips:
    skb: the kernel structure that represents the data that is transfered.
    sk: the kernel structure that links skb and process(task_struct).
    route: for egress, the routing is to find the outbound interface, for ingress, the routing is to forward the traffic, or to pass the skb to the sk that it belongs to.
```