use crate::{
    error::{SubstitutionError, SubstitutionResult},
    names::{AsSet, AutNum, FilterSet, RouteSet},
    primitive::SetNameComp,
};

/// A type that can provide a value for substituting `PeerAS` tokens in RPSL
/// expressions.
pub trait PeerAs {
    /// Get the [`AutNum`] value to substitute for `PeerAS` tokens, if available,
    /// or [`None`] otherwise.
    fn peeras(&self) -> Option<&AutNum>;
}

impl PeerAs for AutNum {
    fn peeras(&self) -> Option<&AutNum> {
        Some(self)
    }
}

macro_rules! debug_substitution {
    ( $node:ty: $ex:expr ) => {
        log::debug!(
            concat!(
                "performing substitution on AST node '",
                stringify!($node),
                "' ({})"
            ),
            $ex
        )
    };
}
pub(crate) use debug_substitution;

/// An RPSL expression in which `PeerAS` tokens may be substituted by
/// [`AutNum`] values.
pub trait Substitute<P: PeerAs>: Sized {
    /// Substitute the `PeerAS` tokens appearing in the RPSL expression with
    /// the value provided by the given [`PeerAs`] object.
    fn substitute(self, p: &P) -> SubstitutionResult<Self>;
}

impl<P: PeerAs> Substitute<P> for FilterSet {
    fn substitute(self, p: &P) -> SubstitutionResult<Self> {
        debug_substitution!(FilterSet: self);
        self.into_iter()
            .map(|component| component.substitute(p))
            .collect()
    }
}

impl<P: PeerAs> Substitute<P> for RouteSet {
    fn substitute(self, p: &P) -> SubstitutionResult<Self> {
        debug_substitution!(RouteSetExpr: self);
        self.into_iter()
            .map(|component| component.substitute(p))
            .collect()
    }
}

impl<P: PeerAs> Substitute<P> for AsSet {
    fn substitute(self, p: &P) -> SubstitutionResult<Self> {
        debug_substitution!(AsSetExpr: self);
        self.into_iter()
            .map(|component| component.substitute(p))
            .collect()
    }
}

impl<P: PeerAs> Substitute<P> for SetNameComp {
    fn substitute(self, p: &P) -> SubstitutionResult<Self> {
        debug_substitution!(SetNameComp: self);
        match self {
            Self::PeerAs => {
                if let Some(peeras) = p.peeras() {
                    Ok(Self::AutNum(*peeras))
                } else {
                    Err(SubstitutionError::PeerAs)
                }
            }
            _ => Ok(self),
        }
    }
}
