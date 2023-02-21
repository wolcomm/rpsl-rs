use std::iter::once;

use ip::{self, traits::PrefixRange, Any, Ipv4, Ipv6};

pub(crate) trait AnyPrefixRange: PrefixRange + 'static {
    fn any() -> Box<dyn Iterator<Item = Self>>;
}

impl AnyPrefixRange for ip::concrete::PrefixRange<Ipv4> {
    fn any() -> Box<dyn Iterator<Item = Self>> {
        Box::new(once(
            "0.0.0.0/0"
                .parse::<Self::Prefix>()
                .map(Self::from)
                .unwrap()
                .or_longer(),
        ))
    }
}

impl AnyPrefixRange for ip::concrete::PrefixRange<Ipv6> {
    fn any() -> Box<dyn Iterator<Item = Self>> {
        Box::new(once(
            "::/0"
                .parse::<Self::Prefix>()
                .map(Self::from)
                .unwrap()
                .or_longer(),
        ))
    }
}

impl AnyPrefixRange for ip::any::PrefixRange {
    fn any() -> Box<dyn Iterator<Item = Self>> {
        Box::new(
            ip::PrefixRange::<Ipv4>::any()
                .map(Self::Ipv4)
                .chain(ip::PrefixRange::<Ipv6>::any().map(Self::Ipv6)),
        )
    }
}
