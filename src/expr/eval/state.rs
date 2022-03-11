#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct New;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct Substituted;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct Expanded;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct Ready;

pub trait State {}

impl State for New {}
impl State for Substituted {}
impl State for Expanded {}
impl State for Ready {}
