//! Septic curve precompile dispatch for the full VM executor.
//!
//! For the POC, the full VM executor path is only required to compile; trace
//! generation for a Septic AIR is not yet implemented. The minimal executor
//! handles the actual computation used by the mock prover.

use crate::{vm::syscall::SyscallRuntime, SyscallCode};

const SEPTIC_POINT_U64_WORDS: usize = 7;

pub(crate) fn septic_add<'a, RT: SyscallRuntime<'a>>(
    rt: &mut RT,
    _syscall_code: SyscallCode,
    arg1: u64,
    arg2: u64,
) -> Option<u64> {
    let p_ptr = arg1;
    assert!(p_ptr.is_multiple_of(8), "p_ptr must be 8-byte aligned");
    let q_ptr = arg2;
    assert!(q_ptr.is_multiple_of(8), "q_ptr must be 8-byte aligned");

    let _p = rt.mr_slice_unsafe(SEPTIC_POINT_U64_WORDS);
    let _q = rt.mr_slice(q_ptr, SEPTIC_POINT_U64_WORDS);

    rt.increment_clk();

    let _w = rt.mw_slice(p_ptr, SEPTIC_POINT_U64_WORDS);

    None
}

pub(crate) fn septic_double<'a, RT: SyscallRuntime<'a>>(
    rt: &mut RT,
    _syscall_code: SyscallCode,
    arg1: u64,
    _arg2: u64,
) -> Option<u64> {
    let p_ptr = arg1;
    assert!(p_ptr.is_multiple_of(8), "p_ptr must be 8-byte aligned");

    let _p = rt.mr_slice_unsafe(SEPTIC_POINT_U64_WORDS);
    let _w = rt.mw_slice(p_ptr, SEPTIC_POINT_U64_WORDS);

    None
}
