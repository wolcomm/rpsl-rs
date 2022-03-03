use std::ops::Deref;

/// traits for performing value substitution on RPSL expressions.
mod subst;
// mod resolve;

// Evaluation states
mod state {
    #[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
    pub struct New;

    #[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
    pub struct Substituted;

    #[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
    pub struct Expanded;

    #[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
    pub struct Resolved<R>(R);

    pub trait State {}

    impl State for New {}
    impl State for Substituted {}
    impl State for Expanded {}
    impl<R> State for Resolved<R> {}
}

use self::state::State;

#[derive(Clone, Debug)]
pub struct Evaluation<T, S: State> {
    expr: T,
    state: S,
}

impl<T, S: State> Deref for Evaluation<T, S> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.expr
    }
}

impl<T, S: State> AsRef<T> for Evaluation<T, S> {
    fn as_ref(&self) -> &T {
        self.deref()
    }
}

impl<T, S: State> Evaluation<T, S> {
    fn into_inner(self) -> T {
        self.expr
    }

    fn state(&self) -> &impl State {
        &self.state
    }
}

impl<T> From<T> for Evaluation<T, state::New> {
    fn from(expr: T) -> Self {
        Evaluation {
            expr,
            state: state::New,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Foo;

    #[test]
    fn local_impl() {
        let e: Evaluation<_, _> = Foo.into();
        assert_eq!(e.state, state::New);
    }
}
