use proptest::{arbitrary::ParamsFor, prelude::*};

use ip::{Any, Ipv4};

use crate::{list::ListOf, primitive::AfiSafi};

use super::{default, policy};

/// Helper trait extending [`LiteralPrefixSetAfi`].
pub trait AfiSafiList: policy::StmtAfi + default::ExprAfi {
    /// Return a [`Strategy`] that yields values of
    /// [`Option<ListOf<AfiSafi>>`] as appropriate to the expression
    /// being generated.
    fn any_afis(
        params: ParamsFor<Option<ListOf<AfiSafi>>>,
    ) -> BoxedStrategy<Option<ListOf<AfiSafi>>>;
}

impl AfiSafiList for Ipv4 {
    fn any_afis(_: ParamsFor<Option<ListOf<AfiSafi>>>) -> BoxedStrategy<Option<ListOf<AfiSafi>>> {
        Just(None).boxed()
    }
}

impl AfiSafiList for Any {
    fn any_afis(
        params: ParamsFor<Option<ListOf<AfiSafi>>>,
    ) -> BoxedStrategy<Option<ListOf<AfiSafi>>> {
        any_with::<Option<ListOf<AfiSafi>>>(params).boxed()
    }
}
