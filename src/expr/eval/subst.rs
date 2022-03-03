use crate::{
    addr_family::LiteralPrefixSetAfi,
    error::SubstitutionError,
    expr::filter,
    names::{AsSet, AutNum, FilterSet, RouteSet},
    primitive::SetNameComp,
};

use super::{state, Evaluation};

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

/// Custom [`Result<T, E>`] containing a possible [`SubstitutionError`].
type SubstitutionResult<T> = Result<T, SubstitutionError>;

/// An RPSL expression in which `PeerAS` tokens may be substituted by
/// [`AutNum`] values.
trait Substitute<P: PeerAs>: Sized {
    /// Substitute the `PeerAS` tokens appearing in the RPSL expression with
    /// the value provided by the given [`PeerAs`] object, wrapping the
    /// resulting value in [`Substituted<T>`].
    fn substitute(self, p: &P) -> SubstitutionResult<Self>;
}

impl<P: PeerAs, T: Substitute<P>> Substitute<P> for Evaluation<T, state::New> {
    fn substitute(self, p: &P) -> SubstitutionResult<Self> {
        Ok(Evaluation {
            expr: self.into_inner().substitute(p)?,
            state: state::New,
        })
    }
}

impl<P: PeerAs, A: LiteralPrefixSetAfi> Substitute<P> for filter::Expr<A> {
    fn substitute(self, p: &P) -> SubstitutionResult<Self> {
        debug_substitution!(Expr: self);
        match self {
            Self::Unit(term) => Ok(Self::Unit(term.substitute(p)?)),
            Self::Not(expr) => Ok(Self::Not(Box::new(expr.substitute(p)?))),
            Self::And(lhs, rhs) => Ok(Self::And(lhs.substitute(p)?, Box::new(rhs.substitute(p)?))),
            Self::Or(lhs, rhs) => Ok(Self::Or(lhs.substitute(p)?, Box::new(rhs.substitute(p)?))),
        }
    }
}

impl<P: PeerAs, A: LiteralPrefixSetAfi> Substitute<P> for filter::Term<A> {
    fn substitute(self, p: &P) -> SubstitutionResult<Self> {
        debug_substitution!(Term: self);
        match self {
            Self::Literal(fltr_literal) => Ok(Self::Literal(fltr_literal.substitute(p)?)),
            Self::Named(fltr_set_expr) => Ok(Self::Named(fltr_set_expr.substitute(p)?)),
            Self::Expr(expr) => Ok(Self::Expr(Box::new(expr.substitute(p)?))),
            any @ Self::Any => Ok(any),
        }
    }
}

impl<P: PeerAs, A: LiteralPrefixSetAfi> Substitute<P> for filter::Literal<A> {
    fn substitute(self, p: &P) -> SubstitutionResult<Self> {
        debug_substitution!(Literal: self);
        match self {
            Self::PrefixSet(set_expr, op) => Ok(Self::PrefixSet(set_expr.substitute(p)?, op)),
            Self::AsPath(_) => unimplemented!("as-path filter literals not yet implemented"),
            attr_match @ Self::AttrMatch(_) => Ok(attr_match),
        }
    }
}

impl<P: PeerAs, A: LiteralPrefixSetAfi> Substitute<P> for filter::PrefixSetExpr<A> {
    fn substitute(self, p: &P) -> SubstitutionResult<Self> {
        debug_substitution!(PrefixSetExpr: self);
        match self {
            literal @ Self::Literal(_) => Ok(literal),
            Self::Named(set) => Ok(Self::Named(set.substitute(p)?)),
        }
    }
}

impl<P: PeerAs> Substitute<P> for filter::NamedPrefixSet {
    fn substitute(self, p: &P) -> SubstitutionResult<Self> {
        debug_substitution!(NamedPrefixSet: self);
        match self {
            Self::PeerAs => {
                if let Some(peeras) = p.peeras() {
                    Ok(Self::AutNum(*peeras))
                } else {
                    Err(SubstitutionError::PeerAs)
                }
            }
            Self::RouteSet(set_expr) => Ok(Self::RouteSet(set_expr.substitute(p)?)),
            Self::AsSet(set_expr) => Ok(Self::AsSet(set_expr.substitute(p)?)),
            _ => Ok(self),
        }
    }
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
        if let SetNameComp::PeerAs = self {
            p.peeras()
                .copied()
                .map(SetNameComp::AutNum)
                .ok_or(SubstitutionError::PeerAs)
        } else {
            Ok(self)
        }
    }
}
