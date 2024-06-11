#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{
        bpf_sock_ops, sk_action::SK_PASS, BPF_ANY, BPF_F_INGRESS,
        BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB, BPF_SOCK_OPS_ALL_CB_FLAGS,
        BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB, BPF_SOCK_OPS_STATE_CB,
    },
    macros::{map, sk_msg, sock_ops},
    maps::SockHash,
    programs::{SkMsgContext, SockOpsContext},
    EbpfContext,
};
use aya_log_ebpf::info;
use ebpf_sk_fastpath_common::{Ipv4Addr, Ipv4Tuple, Ipv6Addr, Ipv6Tuple};

const AF_INET: u32 = 2;
// const AF_INET6: u32 = 10;

pub fn get_tuple_v4(ctx: &SockOpsContext) -> Ipv4Tuple {
    let src = Ipv4Addr::new(ctx.local_ip4(), ctx.local_port());
    let dst = Ipv4Addr::new(ctx.remote_ip4(), ctx.remote_port().to_be());
    Ipv4Tuple::new(ctx.family(), src, dst)
}

pub fn get_tuple_v6(ctx: &SockOpsContext) -> Ipv6Tuple {
    let src = Ipv6Addr::new(ctx.local_ip6(), ctx.local_port());
    let dst = Ipv6Addr::new(ctx.remote_ip6(), ctx.remote_port().to_be());
    Ipv6Tuple::new(ctx.family(), src, dst)
}

const fn code_to_str(code: i64) -> &'static str {
    match code {
        0 => "SK_DROP",
        1 => "SK_PASS",
        _ => "UNKNOWN",
    }
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
            let op = if ctx.op() == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB {
                "ACTIVE_ESTABLISHED_CB"
            } else {
                "PASSIVE_ESTABLISHED_CB"
            };
            let family = ctx.family();
            if family == AF_INET {
                let mut tuple = get_tuple_v4(&ctx);
                // only handle local => local connection
                // TODO: use a map of rules to do the verdict
                // you may refer to: https://mbertrone.github.io/documents/21-Securing_Linux_with_a_Faster_and_Scalable_Iptables.pdf
                if !(tuple.src.addr == 0x100007f && tuple.dst.addr == 0x100007f) {
                    return Ok(0);
                }
                info!(
                    &ctx,
                    "[sockops-{}] from {:i}:{} => {:i}:{}",
                    op,
                    tuple.src.addr.to_be(),
                    tuple.src.port,
                    tuple.dst.addr.to_be(),
                    tuple.dst.port
                );
                let _ = ctx.set_cb_flags(BPF_SOCK_OPS_ALL_CB_FLAGS as _);
                unsafe {
                    let _ = INTERCEPT_EGRESS_V4.update(&mut tuple, &mut (*ctx.ops), BPF_ANY as _);
                }
            } else {
                info!(&ctx, "UnSupported family: {}", family)
            }
        }
        BPF_SOCK_OPS_STATE_CB => {
            let family = ctx.family();
            // this check is unnecessary, since only the qualified sk will trigger the state_cb
            // (it's set via bpf_sock_ops_cb_flags_set when the connection is established)
            if family == AF_INET {
                let tuple = get_tuple_v4(&ctx);
                let ptr = ctx.as_ptr() as *const bpf_sock_ops;
                if ptr.is_null() {
                    return Ok(0);
                }
                let ptr = unsafe { &*ptr };
                let args = unsafe { &ptr.__bindgen_anon_1.args };
                let old_state = args[0];
                let new_state = args[1];
                info!(
                    &ctx,
                    "[sockops-STATE_CB] from {:i}:{} => {:i}:{}, old_state: {}, new_state: {}",
                    tuple.src.addr.to_be(),
                    tuple.src.port,
                    tuple.dst.addr.to_be(),
                    tuple.dst.port,
                    old_state,
                    new_state
                );
                // TODO: when the new state is BPF_TCP_CLOSE, we can delete the tuple from the map
                // but it's not supported in current SockOpsContext's API
            }
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
    let sk_msg_md = unsafe { &mut *(ctx.msg) };
    let family = sk_msg_md.family;
    if family == AF_INET {
        let tuple = Ipv4Tuple::new(
            family,
            Ipv4Addr::new(sk_msg_md.local_ip4, sk_msg_md.local_port),
            Ipv4Addr::new(sk_msg_md.remote_ip4, sk_msg_md.remote_port.swap_bytes()),
        );
        info!(
            &ctx,
            "[sk_msg] {:i}:{} => {:i}:{}",
            tuple.src.addr.to_be(),
            tuple.src.port,
            tuple.dst.addr.to_be(),
            tuple.dst.port,
        );
        // 16777343 is the u32 of 127.0.0.1
        if tuple.src.addr == 0x100007f && tuple.dst.addr == 0x100007f {
            // FIXME: the other side of the sk might be a different family, so we need to check both V4 and V6 sock_map **in the real world**
            let mut target_sk = tuple.reverse();
            let ret = INTERCEPT_EGRESS_V4.redirect_msg(&ctx, &mut target_sk, BPF_F_INGRESS as _);
            let ret_str = code_to_str(ret);
            info!(&ctx, "redirect_msg verdict result: {}", ret_str);
            return Ok(ret as _);
        }
    }

    Ok(SK_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
