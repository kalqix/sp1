use slop_algebra::{AbstractField, PrimeField32};
use sp1_hypercube::{septic_curve::SepticCurve, septic_extension::SepticExtension};
use sp1_jit::SyscallContext;
use sp1_primitives::SP1Field;

/// Number of u64 words used to hold a septic curve point in memory (14 u32 words = 7 u64 words).
const SEPTIC_POINT_U64_WORDS: usize = 7;

fn u64_words_to_septic_point<'a>(
    words: impl IntoIterator<Item = &'a u64>,
) -> SepticCurve<SP1Field> {
    let mut elems = [SP1Field::zero(); 14];
    for (i, w) in words.into_iter().enumerate() {
        elems[2 * i] = SP1Field::from_canonical_u32(*w as u32);
        elems[2 * i + 1] = SP1Field::from_canonical_u32((*w >> 32) as u32);
    }
    SepticCurve {
        x: SepticExtension([elems[0], elems[1], elems[2], elems[3], elems[4], elems[5], elems[6]]),
        y: SepticExtension([
            elems[7], elems[8], elems[9], elems[10], elems[11], elems[12], elems[13],
        ]),
    }
}

fn septic_point_to_u64_words(point: &SepticCurve<SP1Field>) -> [u64; SEPTIC_POINT_U64_WORDS] {
    let mut elems = [0u32; 14];
    for i in 0..7 {
        elems[i] = point.x.0[i].as_canonical_u32();
        elems[7 + i] = point.y.0[i].as_canonical_u32();
    }
    let mut out = [0u64; SEPTIC_POINT_U64_WORDS];
    for i in 0..SEPTIC_POINT_U64_WORDS {
        out[i] = (elems[2 * i] as u64) | ((elems[2 * i + 1] as u64) << 32);
    }
    out
}

/// Execute a septic curve add assign syscall.
pub(crate) unsafe fn septic_add(
    ctx: &mut impl SyscallContext,
    arg1: u64,
    arg2: u64,
) -> Option<u64> {
    let p_ptr = arg1;
    if !p_ptr.is_multiple_of(8) {
        panic!();
    }
    let q_ptr = arg2;
    if !q_ptr.is_multiple_of(8) {
        panic!();
    }

    let p_point = u64_words_to_septic_point(ctx.mr_slice_unsafe(p_ptr, SEPTIC_POINT_U64_WORDS));
    let q_point = u64_words_to_septic_point(ctx.mr_slice(q_ptr, SEPTIC_POINT_U64_WORDS));

    let result = p_point.add_incomplete(q_point);
    let result_words = septic_point_to_u64_words(&result);

    ctx.bump_memory_clk();
    ctx.mw_slice(p_ptr, &result_words);

    None
}

/// Execute a septic curve double assign syscall.
pub(crate) unsafe fn septic_double(
    ctx: &mut impl SyscallContext,
    arg1: u64,
    _arg2: u64,
) -> Option<u64> {
    let p_ptr = arg1;
    if !p_ptr.is_multiple_of(8) {
        panic!();
    }

    let p_point = u64_words_to_septic_point(ctx.mr_slice_unsafe(p_ptr, SEPTIC_POINT_U64_WORDS));
    let result = p_point.double();
    let result_words = septic_point_to_u64_words(&result);

    ctx.mw_slice(p_ptr, &result_words);

    None
}
