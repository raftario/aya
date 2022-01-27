use libc::if_nametoindex;
use std::{ffi::CString, os::unix::io::RawFd};

use crate::{
    generated::{bpf_attach_type, bpf_prog_type::BPF_PROG_TYPE_SK_LOOKUP},
    programs::{load_program, FdLink, LinkRef, ProgramData, ProgramError},
    sys::bpf_link_create,
};

/// A sk_lookup program.
///
/// sk_lookup programs can be used to select which socket should
/// receive new incoming packets. They can be used to listen to a
/// select range of addresses or ports from a single socket.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 5.9.
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_SK_LOOKUP")]
pub struct SkLookup {
    pub(crate) data: ProgramData,
}

impl SkLookup {
    /// Loads the program inside the kernel.
    ///
    /// See also [`Program::load`](crate::programs::Program::load).
    pub fn load(&mut self) -> Result<(), ProgramError> {
        self.data.expected_attach_type = Some(bpf_attach_type::BPF_SK_LOOKUP);
        load_program(BPF_PROG_TYPE_SK_LOOKUP, &mut self.data)
    }

    /// Attaches the program to the given `interface`.
    ///
    /// # Errors
    ///
    /// If the given `interface` does not exist
    /// [`ProgramError::UnknownInterface`] is returned.
    ///
    /// When attaching fails, [`ProgramError::SyscallError`] is returned.
    pub fn attach(&mut self, interface: &str) -> Result<LinkRef, ProgramError> {
        let prog_fd = self.data.fd_or_err()?;
        let c_interface = CString::new(interface).unwrap();
        let if_index = unsafe { if_nametoindex(c_interface.as_ptr()) } as RawFd;
        if if_index == 0 {
            return Err(ProgramError::UnknownInterface {
                name: interface.to_string(),
            });
        }

        let link_fd = bpf_link_create(prog_fd, if_index, bpf_attach_type::BPF_SK_LOOKUP, None, 0)
            .map_err(|(_, io_error)| ProgramError::SyscallError {
                call: "bpf_link_create".to_owned(),
                io_error,
            })? as RawFd;
        Ok(self.data.link(FdLink { fd: Some(link_fd) }))
    }
}
