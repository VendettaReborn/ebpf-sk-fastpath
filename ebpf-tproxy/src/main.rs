use aya::maps::SockHash;
use aya::programs::{SkMsg, SockOps};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use common::Ipv4Tuple;
use log::{debug, info, warn};
use tokio::signal;

#[allow(unused)]
mod common;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "/sys/fs/cgroup/unified")]
    cgroup_path: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/ebpf-tproxy"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/ebpf-tproxy"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    {
        let program: &mut SockOps = bpf.program_mut("tproxy_sockops").unwrap().try_into()?;
        let cgroup = std::fs::File::open(opt.cgroup_path)?;
        program.load()?;
        program.attach(cgroup)?;
    }

    {
        let intercept_egress =
            SockHash::<_, Ipv4Tuple>::try_from(bpf.map("INTERCEPT_EGRESS_V4").unwrap())?;
        let map_fd = intercept_egress.fd().try_clone()?;
        let program: &mut SkMsg = bpf.program_mut("tproxy_msg").unwrap().try_into()?;
        program.load()?;
        program.attach(&map_fd)?;
    }

    // TODO: support ipv6

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}

#[cfg(test)]
mod tests {
    use bytes::BufMut;

    #[test]
    fn t1() {
        let mut raw = [0; 10];
        let mut buf = tokio::io::ReadBuf::new(&mut raw);
        let body = &[1; 12];

        let mut read_buf = bytes::BytesMut::new();

        let to_read = &body[..buf.remaining()];
        let to_buf = &body[buf.remaining()..];
        buf.put_slice(to_read);
        // use put_slice instead of clone_from_slice
        read_buf.put_slice(to_buf);

        assert!(buf.filled().len() == 10);
        assert!(read_buf.len() == 2);
    }
}
