mod solver;

pub use solver::{alloc, dealloc, is_valid_params, required_proof_len, solve_once};

#[cfg(test)]
mod tests {
    use super::{is_valid_params, required_proof_len, solve_once};

    #[test]
    fn legal_domain_and_proof_lengths() {
        for n in (8..=256).step_by(2) {
            for k in 2..=8 {
                assert_eq!(is_valid_params(n, k), n % (k + 1) == 0);
            }
        }
        assert_eq!(required_proof_len(5), 128);
        assert_eq!(required_proof_len(1), 0);
        assert_eq!(required_proof_len(9), 0);
    }

    #[test]
    fn abi_rejects_invalid_inputs_and_short_output() {
        let seed = [1u8, 2, 3];
        let nonce = [4u8, 5, 6, 7];
        let mut out = [0u8; 128];
        assert!(
            solve_once(
                seed.as_ptr(),
                seed.len() as u32,
                nonce.as_ptr(),
                nonce.len() as u32,
                96,
                8,
                64,
                out.as_mut_ptr(),
                out.len() as u32
            ) < 0
        );
        let mut short = [0u8; 127];
        assert!(
            solve_once(
                seed.as_ptr(),
                seed.len() as u32,
                nonce.as_ptr(),
                nonce.len() as u32,
                90,
                5,
                16,
                short.as_mut_ptr(),
                short.len() as u32
            ) < 0
        );
    }

    #[test]
    fn solve_small_profile_keeps_odd_intermediate_layer() {
        let seed: [u8; 32] = std::array::from_fn(|index| index as u8);
        let mut nonce = [0u8; 24];
        nonce[23] = 5;
        let mut out = [0u8; 64];
        let rc = solve_once(
            seed.as_ptr(),
            seed.len() as u32,
            nonce.as_ptr(),
            nonce.len() as u32,
            12,
            2,
            64,
            out.as_mut_ptr(),
            out.len() as u32,
        );
        assert_eq!(rc, 16);
        let mut indices = [0u32; 4];
        for (position, value) in indices.iter_mut().enumerate() {
            let start = position * 4;
            *value =
                u32::from_be_bytes([out[start], out[start + 1], out[start + 2], out[start + 3]]);
        }
        assert_eq!(indices, [2, 32, 40, 41]);
    }

    #[test]
    fn solve_default_fixture_returns_a_proof() {
        let seed = *b"0123456789abcdefghijklmnopqrstuv";
        let nonce = [0u8; 24];
        let mut out = [0u8; 128];
        let rc = solve_once(
            seed.as_ptr(),
            seed.len() as u32,
            nonce.as_ptr(),
            nonce.len() as u32,
            90,
            5,
            65536,
            out.as_mut_ptr(),
            out.len() as u32,
        );
        assert_eq!(rc, 128);
    }

    #[test]
    fn resource_failure_is_explicit_and_recovery_keeps_parameters() {
        let seed = [0u8; 32];
        let nonce = [0u8; 24];
        let mut out = [0u8; 128];
        let resource = solve_once(
            seed.as_ptr(),
            seed.len() as u32,
            nonce.as_ptr(),
            nonce.len() as u32,
            90,
            5,
            u32::MAX,
            out.as_mut_ptr(),
            out.len() as u32,
        );
        assert_eq!(resource, -2);

        let layered_resource = solve_once(
            seed.as_ptr(),
            seed.len() as u32,
            nonce.as_ptr(),
            nonce.len() as u32,
            12,
            2,
            512,
            out.as_mut_ptr(),
            out.len() as u32,
        );
        assert_eq!(layered_resource, -2);

        let mut small_nonce = [0u8; 24];
        small_nonce[23] = 5;
        let small_seed: [u8; 32] = std::array::from_fn(|index| index as u8);
        assert_eq!(
            solve_once(
                small_seed.as_ptr(),
                small_seed.len() as u32,
                small_nonce.as_ptr(),
                small_nonce.len() as u32,
                12,
                2,
                64,
                out.as_mut_ptr(),
                out.len() as u32
            ),
            16
        );
    }
}
