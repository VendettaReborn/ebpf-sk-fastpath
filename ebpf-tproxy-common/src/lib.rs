#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ipv4Addr {
    pub addr: u32,
    pub port: u32,
}

impl Ipv4Addr {
    pub fn new(addr: u32, port: u32) -> Ipv4Addr {
        Ipv4Addr { addr, port }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ipv4Tuple {
    pub protocol: u32,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
}

impl Ipv4Tuple {
    pub fn new(protocol: u32, src: Ipv4Addr, dst: Ipv4Addr) -> Ipv4Tuple {
        Ipv4Tuple { protocol, src, dst }
    }
}

pub struct Ipv6Addr {
    pub addr: [u32; 4],
    pub port: u32,
}

impl Ipv6Addr {
    pub fn new(addr: [u32; 4], port: u32) -> Ipv6Addr {
        Ipv6Addr { addr, port }
    }
}

pub struct Ipv6Tuple {
    pub protocol: u32,
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
}

impl Ipv6Tuple {
    pub fn new(protocol: u32, src: Ipv6Addr, dst: Ipv6Addr) -> Ipv6Tuple {
        Ipv6Tuple { protocol, src, dst }
    }
}
