use crate::{addr_family::Afi, primitive::IpPrefix};

use super::{len_range::PrefixLengthRangeIter, IpPrefixRange};

pub struct IpPrefixRangeIter<A: Afi> {
    prefix: IpPrefix<A>,
    len_iter: PrefixLengthRangeIter<A>,
    subnets: Option<A::Subnets>,
}

impl<A: Afi> From<IpPrefixRange<A>> for IpPrefixRangeIter<A> {
    fn from(range: IpPrefixRange<A>) -> Self {
        Self {
            prefix: range.prefix,
            len_iter: range.len_range.into_iter(),
            subnets: None,
        }
    }
}

impl<A: Afi> Iterator for IpPrefixRangeIter<A> {
    type Item = IpPrefix<A>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(mut subnets) = self.subnets.take() {
                if let Some(prefix) = subnets.next() {
                    self.subnets = Some(subnets);
                    return Some(IpPrefix::new(prefix));
                }
            }
            if let Some(len) = self.len_iter.next() {
                // unwrap ok because len is guaranteed to be an acceptable
                // more-specific length for prefix
                self.subnets = A::net_to_subnets(self.prefix.as_ref(), *len.as_ref()).ok();
            } else {
                return None;
            }
        }
    }
}
