//! How much of an I1-I5 chain the Linux kernel module can carry.
//!
//! amneziawg-go reads chains over its text UAPI and has no budget to speak of.
//! The kernel module is configured over generic netlink, where the whole device
//! travels in one message of one page:
//!
//! * amneziawg-tools `src/ipc-linux.h`, `kernel_set_device`, writes every
//!   device attribute (I1-I5 included) with the unchecked `mnl_attr_put_strz`
//!   into a buffer of `mnl_ideal_socket_buffer_size()` bytes, the page size
//!   capped at 8192. Peers spill into a second message; device attributes do
//!   not.
//! * amneziawg-linux-kernel-module `src/netlink.c`, `wg_get_device_dump`, puts
//!   the same attributes into the first skb of the dump. When they do not fit it
//!   returns `-EMSGSIZE`: `awg show` prints "Unable to access interface: Message
//!   too long" while awg-quick brings the interface up anyway. The tunnel looks
//!   configured and carries nothing.
//!
//! That skb is `NLMSG_GOODSIZE`, 3776 bytes on 4 KiB pages, and the rest of the
//! device takes about 344 of them. What is left for I1-I5 is about 3432 bytes;
//! the budget keeps a margin under it for attributes a later release adds.
//!
//! Ported from Architect `generator/chainBudget.ts` (issue #17 there: five SIP
//! REGISTER chains came to 3820 bytes).

/// Netlink bytes the I1-I5 attributes may take together.
pub const KMOD_CHAIN_BUDGET: u32 = 3200;

/// What one chain costs on the wire: a 4-byte attribute header, the string with
/// its terminating NUL, and padding to the next 4-byte boundary (`NLA_ALIGN`).
/// An empty chain is not sent at all.
pub fn chain_attr_bytes(chain: &str) -> u32 {
    if chain.is_empty() {
        return 0;
    }
    4 + (chain.len() as u32 + 1).div_ceil(4) * 4
}

/// What a whole I1-I5 set costs.
pub fn chain_bytes<S: AsRef<str>>(chains: &[S]) -> u32 {
    chains.iter().map(|c| chain_attr_bytes(c.as_ref())).sum()
}

/// Bring a chain set under `budget`, giving up as little as possible.
///
/// I1 is the packet the profile exists for, so it is never touched. From I5
/// down each slot is first swapped for what `fallback` builds (an entropy
/// packet, a fraction of a text protocol's size), and only when that is still
/// not enough are slots dropped, again from I5 down. Dropping one is not an
/// error: the device sends the chains it has and skips the empty ones.
pub fn fit<const N: usize>(
    mut chains: [String; N],
    mut fallback: impl FnMut(usize) -> String,
    budget: u32,
) -> [String; N] {
    for slot in (1..N).rev() {
        if chain_bytes(&chains) <= budget {
            break;
        }
        if chains[slot].is_empty() {
            continue;
        }
        let replacement = fallback(slot);
        if chain_attr_bytes(&replacement) < chain_attr_bytes(&chains[slot]) {
            chains[slot] = replacement;
        }
    }
    for slot in (1..N).rev() {
        if chain_bytes(&chains) <= budget {
            break;
        }
        chains[slot].clear();
    }
    chains
}

#[cfg(test)]
mod tests {
    use super::*;

    fn long() -> String {
        format!("<b 0x{}>", "ab".repeat(400))
    }

    #[test]
    fn counts_the_header_the_nul_and_the_alignment() {
        assert_eq!(chain_attr_bytes(""), 0);
        // 3 chars + NUL = 4, no padding.
        assert_eq!(chain_attr_bytes("<t>"), 8);
        // 4 chars + NUL = 5, padded to 8.
        assert_eq!(chain_attr_bytes("<rc>"), 12);
        assert_eq!(chain_bytes(&["<t>", "", "<t>"]), 16);
    }

    #[test]
    fn a_set_under_the_budget_is_left_alone() {
        let set = ["<t>", "<r 10>", "", "", ""].map(String::from);
        assert_eq!(fit(set.clone(), |_| "<r 5>".into(), KMOD_CHAIN_BUDGET), set);
    }

    #[test]
    fn trailing_slots_are_swapped_first_and_i1_never() {
        let set: [String; 5] = std::array::from_fn(|_| long());
        let out = fit(set, |_| "<r 40>".into(), 2000);
        assert_eq!(out[0], long());
        assert!(chain_bytes(&out) <= 2000);
        // Replacing I5..I3 was enough, so I2 survived.
        assert_eq!(out[1], long());
        assert_eq!(out[4], "<r 40>");
    }

    #[test]
    fn slots_are_dropped_when_the_fallback_is_no_smaller() {
        let set: [String; 3] = std::array::from_fn(|_| long());
        let out = fit(set, |_| long(), 1000);
        assert_eq!(out, [long(), String::new(), String::new()]);
    }
}
