#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{
        sk_action::SK_PASS, BPF_ANY, BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB, BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB, BPF_SOCK_OPS_STATE_CB
    },
    macros::{map, sk_msg, sock_ops},
    maps::SockHash,
    programs::{SkMsgContext, SockOpsContext},
};
use aya_log_ebpf::info;
use ebpf_tproxy_common::{Ipv4Addr, Ipv4Tuple, Ipv6Addr, Ipv6Tuple};

const AF_INET: u32 = 2;
// const AF_INET6: u32 = 10;

pub fn get_tuple_v4(ctx: &SockOpsContext) -> Ipv4Tuple {
    let src = Ipv4Addr::new(ctx.local_ip4(), ctx.local_port());
    let dst = Ipv4Addr::new(ctx.remote_ip4(), ctx.remote_port().swap_bytes());
    Ipv4Tuple::new(ctx.family(), src, dst)
}

pub fn get_tuple_v6(ctx: &SockOpsContext) -> Ipv6Tuple {
    let src = Ipv6Addr::new(ctx.local_ip6(), ctx.local_port());
    let dst = Ipv6Addr::new(ctx.remote_ip6(), ctx.remote_port().swap_bytes());
    Ipv6Tuple::new(ctx.family(), src, dst)
}

#[map]
static INTERCEPT_EGRESS_V4: SockHash<Ipv4Tuple> = SockHash::with_max_entries(1024, 0);

#[map]
static INTERCEPT_EGRESS_V6: SockHash<Ipv6Tuple> = SockHash::with_max_entries(1024, 0);

#[sock_ops]
pub fn tproxy_sockops(ctx: SockOpsContext) -> u32 {
    match try_tproxy_sockops(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tproxy_sockops(ctx: SockOpsContext) -> Result<u32, u32> {
    match ctx.op() {
        // local => remote, remote => local conn request
        BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB | BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB => {
            info!(
                &ctx,
                "{}",
                if ctx.op() == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB {
                    "BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB"
                } else {
                    "BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB"
                }
            );
            let family = ctx.family();
            if family == AF_INET {
                let mut tuple = get_tuple_v4(&ctx);
                // TODO: log tuple here
                info!(
                    &ctx,
                    "from {:i}:{} => {:i}:{}",
                    tuple.src.addr.swap_bytes(),
                    tuple.src.port,
                    tuple.dst.addr.swap_bytes(),
                    tuple.dst.port
                );
                unsafe {
                    let _ = INTERCEPT_EGRESS_V4.update(&mut tuple, &mut (*ctx.ops), BPF_ANY as _);
                }
            } else {
                info!(&ctx, "UnSupported family: {}", family)
            }
        }
        BPF_SOCK_OPS_STATE_CB => {
            info!(&ctx, "BPF_SOCK_OPS_STATE_CB");
        }
        _ => {}
    }
    Ok(0)
}

#[sk_msg]
pub fn tproxy_msg(ctx: SkMsgContext) -> u32 {
    match try_tproxy_msg(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tproxy_msg(ctx: SkMsgContext) -> Result<u32, u32> {
    // TODO: log msg's tuple here, verify the tuple also shows in the INTERCEPT_EGRESS_V4
    info!(&ctx, "tproxy_msg");
    Ok(SK_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
