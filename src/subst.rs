use std::fmt;

use crate::{
    addr_family::LiteralPrefixSetAfi,
    error::{SubstitutionError, SubstitutionResult},
    expr::filter::{Expr, Literal, NamedPrefixSet, PrefixSetExpr, Term},
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

/// An RPSL expression in which `PeerAS` tokens may be substituted by
/// [`AutNum`] values.
pub trait Substitute<P: PeerAs>: Sized {
    /// Substitute the `PeerAS` tokens appearing in the RPSL expression with
    /// the value provided by the given [`PeerAs`] object.
    fn substitute(self, p: &P) -> SubstitutionResult<Self>;
}

impl<P, A> Substitute<P> for Expr<A>
where
    P: PeerAs,
    A: LiteralPrefixSetAfi,
{
    fn substitute(self, p: &P) -> SubstitutionResult<Self> {
        log::info!(
            "trying to substitute 'PeerAS' tokens in filter expression '{}'",
            self
        );
        debug_substitution!(Expr: self);
        match self {
            Self::Unit(term) => Ok(Self::Unit(term.substitute(p)?)),
            Self::Not(expr) => Ok(Self::Not(Box::new(expr.substitute(p)?))),
            Self::And(lhs, rhs) => Ok(Self::And(lhs.substitute(p)?, Box::new(rhs.substitute(p)?))),
            Self::Or(lhs, rhs) => Ok(Self::Or(lhs.substitute(p)?, Box::new(rhs.substitute(p)?))),
        }
    }
}

impl<P, A> Substitute<P> for Term<A>
where
    P: PeerAs,
    A: LiteralPrefixSetAfi,
{
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

impl<P, A> Substitute<P> for Literal<A>
where
    P: PeerAs,
    A: LiteralPrefixSetAfi,
{
    fn substitute(self, p: &P) -> SubstitutionResult<Self> {
        debug_substitution!(Literal: self);
        match self {
            Self::PrefixSet(set_expr, op) => Ok(Self::PrefixSet(set_expr.substitute(p)?, op)),
            Self::AsPath(_) => unimplemented!("as-path filter literals not yet implemented"),
            attr_match @ Self::AttrMatch(_) => Ok(attr_match),
        }
    }
}

impl<P, A> Substitute<P> for PrefixSetExpr<A>
where
    P: PeerAs,
    A: LiteralPrefixSetAfi,
{
    fn substitute(self, p: &P) -> SubstitutionResult<Self> {
        debug_substitution!(PrefixSetExpr: self);
        match self {
            literal @ Self::Literal(_) => Ok(literal),
            Self::Named(set) => Ok(Self::Named(set.substitute(p)?)),
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

impl<P: PeerAs> Substitute<P> for NamedPrefixSet {
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
