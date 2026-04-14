#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// Adds two septic curve points.
///
/// The result is stored in the first point.
///
/// Each point is laid out as 7 contiguous u64 words representing 14 KoalaBear
/// field elements: `[x0, x1, x2, x3, x4, x5, x6, y0, y1, y2, y3, y4, y5, y6]`,
/// packed two per u64 (little-endian).
///
/// ### Safety
///
/// The caller must ensure that `p` and `q` are valid pointers aligned to 8 bytes
/// and that `p != q`. The points must satisfy the incomplete weierstrass addition
/// preconditions (use `syscall_septic_double` for `P + P`).
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_septic_add(p: *mut [u64; 7], q: *const [u64; 7]) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::syscalls::SEPTIC_ADD,
            in("a0") p,
            in("a1") q
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// Doubles a septic curve point.
///
/// The result is stored in-place in the supplied buffer.
///
/// ### Safety
///
/// The caller must ensure that `p` is a valid pointer aligned to 8 bytes.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_septic_double(p: *mut [u64; 7]) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::syscalls::SEPTIC_DOUBLE,
            in("a0") p,
            in("a1") 0
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
