use std::cmp::Ordering;
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;
use std::ops::Bound;

use ranges::Domain;

use crate::addr_family::Afi;

use super::{EvaluationError, EvaluationResult};

macro_rules! err {
    ( $( $arg:tt )* ) => {
        super::error::err!(
            super::error::EvaluationErrorKind::PrefixLengthValidation,
            $($arg)*
        )
    };
}

#[derive(Copy, Clone, Debug)]
pub struct PrefixLength<A: Afi>(u8, PhantomData<A>);

impl<A: Afi> PrefixLength<A> {
    const MIN: u8 = 0;
    const MAX: u8 = A::MAX_PREFIX_LEN;

    pub fn from_bound<F>(bound: Bound<&Self>, neighbor: F) -> Option<Self>
    where
        F: FnOnce(&Self) -> Option<Self>,
    {
        match bound {
            Bound::Included(len) => Some(*len),
            Bound::Excluded(len) => neighbor(len),
            Bound::Unbounded => unreachable!("prefix-length ranges cannot be unbounded"),
        }
    }
}

impl<A: Afi> Hash for PrefixLength<A> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state)
    }
}
impl<A: Afi> PartialEq for PrefixLength<A> {
    fn eq(&self, rhs: &Self) -> bool {
        self.as_ref().eq(rhs.as_ref())
    }
}
impl<A: Afi> Eq for PrefixLength<A> {}
impl<A: Afi> PartialOrd for PrefixLength<A> {
    fn partial_cmp(&self, rhs: &Self) -> Option<Ordering> {
        self.as_ref().partial_cmp(rhs.as_ref())
    }
}
impl<A: Afi> Ord for PrefixLength<A> {
    fn cmp(&self, rhs: &Self) -> Ordering {
        self.as_ref().cmp(rhs.as_ref())
    }
}

impl<A: Afi> AsRef<u8> for PrefixLength<A> {
    fn as_ref(&self) -> &u8 {
        &self.0
    }
}

impl<A: Afi> fmt::Display for PrefixLength<A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.as_ref().fmt(f)
    }
}

impl<A: Afi> TryFrom<u8> for PrefixLength<A> {
    type Error = EvaluationError;

    fn try_from(len: u8) -> EvaluationResult<Self> {
        if Self::MAX < len {
            Err(err!("invalid prefix length {}", len))
        } else {
            Ok(Self(len, PhantomData))
        }
    }
}

impl<A: Afi> Domain for PrefixLength<A> {
    const DISCRETE: bool = true;

    fn minimum() -> Bound<Self> {
        Bound::Included(Self::MIN.try_into().unwrap())
    }

    fn maximum() -> Bound<Self> {
        Bound::Included(Self::MAX.try_into().unwrap())
    }

    fn predecessor(&self) -> Option<Self> {
        (self.as_ref() - 1).try_into().ok()
    }

    fn successor(&self) -> Option<Self> {
        (self.as_ref() + 1).try_into().ok()
    }
}
