use std::convert::{TryFrom, TryInto};
use std::fmt::{self, Debug};
use std::iter::{Extend, FromIterator};
use std::ops::{BitAnd, BitOr, Not};

use crate::{
    addr_family::Afi,
    primitive::{IpPrefix, IpPrefixRange as AstIpPrefixRange},
};

use super::{
    apply::Apply,
    error::{self, EvaluationError, EvaluationResult},
};

mod enums;
mod iter;
mod len;
mod len_range;

use self::iter::IpPrefixRangeIter;

macro_rules! err {
    ( $( $arg:tt )* ) => {
        super::error::err!(
            super::error::EvaluationErrorKind::PrefixRangeConstruction,
            $($arg)*
        )
    };
}

pub use self::{enums::IpPrefixRangeEnum, len_range::PrefixLengthRange};

pub trait PrefixSet<A: Afi>
where
    Self: Default
        + Debug
        + Not<Output = Self>
        + BitAnd<Output = Self>
        + BitOr<Output = Self>
        + Extend<IpPrefixRange<A>>
        + FromIterator<IpPrefixRange<A>>
        + IntoIterator<Item = IpPrefixRange<A>>,
{
    fn empty() -> Self {
        Self::default()
    }

    fn any() -> Self {
        let mut set = Self::empty();
        set.extend(Some(IpPrefixRange::all()));
        set
    }
}

pub struct IpPrefixRange<A: Afi> {
    prefix: IpPrefix<A>,
    len_range: PrefixLengthRange<A>,
}

impl<A: Afi> IpPrefixRange<A> {
    pub fn new(prefix: IpPrefix<A>, len_range: PrefixLengthRange<A>) -> EvaluationResult<Self> {
        let prefix_len = A::prefix_len(prefix.as_ref()).try_into()?;
        let range_start = len_range
            .start()
            .ok_or_else(|| err!("invalid prefix length-range start bound"))?;
        if range_start < prefix_len {
            Err(err!(
                "invalid length range {} for prefix {}",
                len_range,
                prefix
            ))
        } else {
            Ok(Self { prefix, len_range })
        }
    }

    pub fn all() -> Self {
        let prefix = IpPrefix::new(A::Net::default());
        let len_range = PrefixLengthRange::full();
        Self { prefix, len_range }
    }

    pub fn prefix(&self) -> &IpPrefix<A> {
        &self.prefix
    }

    pub fn len_range(&self) -> &PrefixLengthRange<A> {
        &self.len_range
    }

    pub fn prefixes(self) -> IpPrefixRangeIter<A> {
        self.into()
    }
}

impl<A: Afi> From<IpPrefix<A>> for IpPrefixRange<A> {
    fn from(prefix: IpPrefix<A>) -> Self {
        let len = A::prefix_len(prefix.as_ref()).try_into().unwrap();
        let len_range = PrefixLengthRange::exact(len);
        Self { prefix, len_range }
    }
}

impl<A: Afi> TryFrom<AstIpPrefixRange<A>> for IpPrefixRange<A> {
    type Error = EvaluationError;

    fn try_from(range: AstIpPrefixRange<A>) -> EvaluationResult<Self> {
        range.operator().apply(range.prefix().to_owned())
    }
}

impl<A: Afi> fmt::Display for IpPrefixRange<A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}^{}", self.prefix, self.len_range,)
    }
}
