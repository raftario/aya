use core::ffi::c_void;

use crate::{bindings::bpf_sk_lookup, BpfContext};

pub struct SkLookupContext {
    pub ctx: *mut bpf_sk_lookup,
}

/// An IP address, either V4 or V6, encoded in network byte order.
pub enum IpAddr {
    V4(u32),
    V6([u32; 4]),
}

impl SkLookupContext {
    pub fn new(ctx: *mut bpf_sk_lookup) -> SkLookupContext {
        SkLookupContext { ctx }
    }

    /// Returns the protocol, either `IPPROTO_TCP` (6) or `IPPROTO_UDP` (17).
    #[inline]
    pub fn protocol(&self) -> u32 {
        unsafe { *self.ctx }.protocol
    }

    #[inline]
    pub fn local_port(&self) -> u32 {
        unsafe { *self.ctx }.local_port
    }

    #[inline]
    pub fn local_ip(&self) -> IpAddr {
        let family = unsafe { *self.ctx }.family;
        match family {
            // AF_INET6
            10 => IpAddr::V6(unsafe { *self.ctx }.local_ip6),
            // AF_INET
            _ => IpAddr::V4(unsafe { *self.ctx }.local_ip4),
        }
    }

    #[inline]
    pub fn remote_port(&self) -> u32 {
        unsafe { *self.ctx }.remote_port
    }

    #[inline]
    pub fn remote_ip(&self) -> IpAddr {
        let family = unsafe { *self.ctx }.family;
        match family {
            // AF_INET6
            10 => IpAddr::V6(unsafe { *self.ctx }.remote_ip6),
            // AF_INET
            _ => IpAddr::V4(unsafe { *self.ctx }.remote_ip4),
        }
    }
}

impl BpfContext for SkLookupContext {
    fn as_ptr(&self) -> *mut c_void {
        self.ctx as *mut _
    }
}
