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

## Benchmarks

we can run both iperf3 server and client with the following command 

server: `iperf3 -s -4` (since we only supports ipv4 now, you can add support of ipv6 by yourself)

client: `iperf3 -c -4 127.0.0.1 -t 10`

### throughput

**before using fastpath**

cmd: `iperf3 --client 127.0.0.1 -t 10`

```txt
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-1.00   sec  3.78 GBytes  32.4 Gbits/sec    0    639 KBytes
[  5]   1.00-2.00   sec  3.05 GBytes  26.2 Gbits/sec    0    639 KBytes
[  5]   2.00-3.00   sec  2.77 GBytes  23.8 Gbits/sec    0    639 KBytes
[  5]   3.00-4.00   sec  3.40 GBytes  29.2 Gbits/sec    0   2.50 MBytes
[  5]   4.00-5.00   sec  4.03 GBytes  34.6 Gbits/sec    0   2.50 MBytes
[  5]   5.00-6.00   sec  3.82 GBytes  32.8 Gbits/sec    0   2.50 MBytes
[  5]   6.00-7.00   sec  3.78 GBytes  32.5 Gbits/sec    0   2.50 MBytes
[  5]   7.00-8.00   sec  3.45 GBytes  29.7 Gbits/sec    0   2.50 MBytes
...
```

**after using fastpath** 

cmd: `iperf3 --client 127.0.0.1 -t 10`

result: 

```txt
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-1.00   sec  4.88 GBytes  41.9 Gbits/sec    0    162 KBytes
[  5]   1.00-2.00   sec  4.78 GBytes  41.1 Gbits/sec    0    162 KBytes
[  5]   2.00-3.00   sec  5.02 GBytes  43.2 Gbits/sec    0    162 KBytes
[  5]   3.00-4.00   sec  5.36 GBytes  46.0 Gbits/sec    0    162 KBytes
[  5]   4.00-5.00   sec  4.87 GBytes  41.8 Gbits/sec    0    162 KBytes
[  5]   5.00-6.00   sec  4.87 GBytes  41.8 Gbits/sec    0    162 KBytes
[  5]   6.00-7.00   sec  4.86 GBytes  41.8 Gbits/sec    0    162 KBytes
[  5]   7.00-8.00   sec  4.77 GBytes  41.0 Gbits/sec    0    162 KBytes
[  5]   8.00-9.00   sec  4.93 GBytes  42.4 Gbits/sec    0    162 KBytes
[  5]   9.00-10.00  sec  4.99 GBytes  42.9 Gbits/sec    0    162 KBytes
...
```

**with proxychain & clash.meta's direct mode**

cmd: `LD_PRELOAD=/usr/lib/libproxychains4.so iperf3 --client 127.0.0.1 -t 10`

result: 

```txt
[  9]   0.00-1.00   sec  3.39 GBytes  29.1 Gbits/sec    0   3.93 MBytes
[  9]   1.00-2.00   sec  2.67 GBytes  22.9 Gbits/sec    0   3.93 MBytes
[  9]   2.00-3.00   sec  3.06 GBytes  26.3 Gbits/sec    0   3.93 MBytes
[  9]   3.00-4.00   sec  2.99 GBytes  25.7 Gbits/sec    0   3.93 MBytes
[  9]   4.00-5.00   sec  2.92 GBytes  25.1 Gbits/sec    0   3.93 MBytes
[  9]   5.00-6.00   sec  3.10 GBytes  26.7 Gbits/sec    0   3.93 MBytes
[  9]   6.00-7.00   sec  2.68 GBytes  23.1 Gbits/sec    0   4.12 MBytes
[  9]   7.00-8.00   sec  2.72 GBytes  23.4 Gbits/sec    0   4.12 MBytes
```

this is just quick verfication of the throughput leap brought by sk_msg's fastpath, to give a more comprehensive benchmark result, we may check other metrics:
1. cpu utilization rate
2. latency

to test the cpu utlization rate, the easiest way is to add `time` before the client's command, aka run `time iperf3 --client 127.0.0.1 -t 10`, and we can get the utilization rate for each case

### cpu utlization rate

**before using fastpath**

```txt
iperf3 --client 127.0.0.1 -t 10  0.04s user 7.41s system 74% cpu 10.006 total
```

**after using fastpath** 

```txt
iperf3 --client 127.0.0.1 -t 10  0.06s user 9.86s system 99% cpu 10.005 total
```

**with proxychain & clash.meta's direct mode**

```txt
LD_PRELOAD=/usr/lib/libproxychains4.so iperf3 --client 127.0.0.1 -t 10  0.05s user 8.02s system 80% cpu 10.008 total
```

comparing the two scenerio, we can basicaly conclude: when the fastpath of sk_msg is enabled, cpu is generally 100% busy with the send/recv job, and that leads to a great throughput performance improvement.

It's reasonable, since the way that when the verdict result is `redirection`, the skb is just stored in a queue that belongs to the other end of the connection, and that end is immediately notified with `sk_data_ready` called. So the kernel doesn't need to poll the backlog of the loopback interface, which is a napi mechanism that cannot fully utilize the cpu.


## TODOS

1. measure the latency
