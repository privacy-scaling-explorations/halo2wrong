use halo2::{
    circuit::{AssignedCell, Region, Value},
    halo2curves::FieldExt,
    plonk::{Advice, Column, Error, Fixed, Selector},
};
use std::collections::BTreeMap;
use utils::decompose;
pub mod ecc;
pub mod integer;
pub mod maingate;
pub mod utils;

#[derive(Debug)]
pub struct RegionCtx<'a, F: FieldExt> {
    region: Region<'a, F>,
    offset: usize,
    cell_map: BTreeMap<u32, AssignedCell<F, F>>,
}
impl<'a, F: FieldExt> RegionCtx<'a, F> {
    pub fn new(region: Region<'a, F>) -> RegionCtx<'a, F> {
        RegionCtx {
            region,
            offset: 0,
            cell_map: BTreeMap::new(),
        }
    }
    pub fn cell_map(&self) -> BTreeMap<u32, AssignedCell<F, F>> {
        self.cell_map.clone()
    }
    pub fn with_map(
        region: Region<'a, F>,
        cell_map: BTreeMap<u32, AssignedCell<F, F>>,
    ) -> RegionCtx<'a, F> {
        RegionCtx {
            region,
            offset: 0,
            cell_map,
        }
    }
    fn copy_chain(&mut self, id: u32, new: AssignedCell<F, F>) -> Result<(), Error> {
        // id == 0 should signal for no copy
        if id != 0 {
            match self.cell_map.get(&id) {
                Some(root) => self.region.constrain_equal(root.cell(), new.cell()),
                None => {
                    self.cell_map.insert(id, new);
                    Ok(())
                }
            }
        } else {
            Ok(())
        }
    }
    fn copy(&mut self, id0: u32, id1: u32) -> Result<(), Error> {
        let cell0 = self
            .cell_map
            .get(&id0)
            .expect("must be assigned to apply copy constraint");
        let cell1 = self
            .cell_map
            .get(&id1)
            .expect("must be assigned to apply copy constraint");
        self.region.constrain_equal(cell0.cell(), cell1.cell())
    }
    fn offset(&self) -> usize {
        self.offset
    }
    fn assign_fixed<A, AR>(
        &mut self,
        annotation: A,
        column: Column<Fixed>,
        value: F,
    ) -> Result<AssignedCell<F, F>, Error>
    where
        A: Fn() -> AR,
        AR: Into<String>,
    {
        self.region
            .assign_fixed(annotation, column, self.offset(), || Value::known(value))
    }
    fn assign_advice<A, AR>(
        &mut self,
        annotation: A,
        column: Column<Advice>,
        value: Value<F>,
    ) -> Result<AssignedCell<F, F>, Error>
    where
        A: Fn() -> AR,
        AR: Into<String>,
    {
        self.region
            .assign_advice(annotation, column, self.offset(), || value)
    }
    fn enable(&mut self, selector: Selector) -> Result<(), Error> {
        selector.enable(&mut self.region, self.offset)
    }
    fn next(&mut self) {
        self.advance_by(1);
    }
    fn advance_by(&mut self, offset: usize) {
        self.offset += offset;
    }
}
pub trait Composable<F: FieldExt>: Sized {
    fn value(&self) -> Value<F>;
    fn compose(terms: &[Self], constant: F) -> Value<F> {
        terms.iter().fold(Value::known(constant), |acc, term| {
            acc.zip(term.value()).map(|(acc, coeff)| acc + coeff)
        })
    }
}
impl<F: FieldExt> Composable<F> for Witness<F> {
    fn value(&self) -> Value<F> {
        self.value
    }
}
impl<F: FieldExt> Composable<F> for Scaled<F> {
    fn value(&self) -> Value<F> {
        self.witness.value().map(|value| value * self.factor)
    }
}
impl<F: FieldExt> Composable<F> for SecondDegreeScaled<F> {
    fn value(&self) -> Value<F> {
        self.w0
            .value()
            .zip(self.w1.value())
            .map(|(w0, w1)| w0 * w1 * self.factor())
    }
}
#[derive(Debug, Clone, Copy)]
pub struct Witness<F: FieldExt> {
    pub(crate) id: u32,
    pub(crate) value: Value<F>,
}
#[derive(Debug, Clone, Copy)]
pub struct Scaled<F: FieldExt> {
    pub(crate) witness: Witness<F>,
    pub(crate) factor: F,
}
#[derive(Debug, Clone, Copy)]
pub struct SecondDegreeScaled<F: FieldExt> {
    pub(crate) w0: Witness<F>,
    pub(crate) w1: Witness<F>,
    pub(crate) factor: F,
}
#[derive(Debug, Clone)]
pub enum Term<F: FieldExt> {
    First(Scaled<F>),
    Second(SecondDegreeScaled<F>),
    Zero,
}
impl<F: FieldExt> Witness<F> {
    pub fn id(&self) -> u32 {
        self.id
    }
    pub fn decompose(&self, number_of_limbs: usize, sublimb_bit_len: usize) -> Value<Vec<F>> {
        self.value()
            .map(|value| decompose(value, number_of_limbs, sublimb_bit_len))
    }
    pub fn dummy() -> Self {
        Self::no_copy(Value::known(F::zero()))
    }
    pub fn no_copy(value: Value<F>) -> Self {
        Witness { id: 0, value }
    }
}
impl<F: FieldExt> Scaled<F> {
    pub fn new(witness: &Witness<F>, factor: F) -> Self {
        Self {
            witness: *witness,
            factor,
        }
    }
    pub fn dummy() -> Self {
        Scaled {
            witness: Witness::dummy(),
            factor: F::zero(),
        }
    }
    pub fn no_copy(value: Value<F>, factor: F) -> Self {
        Self::new(&Witness::no_copy(value), factor)
    }
    pub fn is_empty(&self) -> bool {
        self.factor == F::zero()
    }
    pub fn mul(witness: &Witness<F>) -> Self {
        Self::new(witness, F::zero())
    }
    pub fn add(witness: &Witness<F>) -> Self {
        Self::new(witness, F::one())
    }
    pub fn neg(&self) -> Self {
        Self::new(&self.witness(), -self.factor())
    }
    pub fn sub(witness: &Witness<F>) -> Self {
        Self::new(witness, -F::one())
    }
    pub fn result(witness: &Witness<F>) -> Self {
        Self::sub(witness)
    }
    pub fn factor(&self) -> F {
        self.factor
    }
    pub fn witness(&self) -> Witness<F> {
        self.witness
    }
    pub fn value(&self) -> Value<F> {
        self.witness.value().map(|e| e * self.factor())
    }
}
impl<F: FieldExt> SecondDegreeScaled<F> {
    pub fn new(w0: &Witness<F>, w1: &Witness<F>, factor: F) -> Self {
        Self {
            w0: *w0,
            w1: *w1,
            factor,
        }
    }
    pub fn is_empty(&self) -> bool {
        self.factor == F::zero()
    }
    pub fn factor(&self) -> F {
        self.factor
    }
    pub fn w0(&self) -> Witness<F> {
        self.w0
    }
    pub fn w1(&self) -> Witness<F> {
        self.w1
    }
}
impl<F: FieldExt> From<Scaled<F>> for Term<F> {
    fn from(e: Scaled<F>) -> Self {
        Self::First(e)
    }
}
impl<F: FieldExt> From<SecondDegreeScaled<F>> for Term<F> {
    fn from(e: SecondDegreeScaled<F>) -> Self {
        Self::Second(e)
    }
}
impl<F: FieldExt> From<&Scaled<F>> for Term<F> {
    fn from(e: &Scaled<F>) -> Self {
        Self::First(*e)
    }
}
impl<F: FieldExt> From<&SecondDegreeScaled<F>> for Term<F> {
    fn from(e: &SecondDegreeScaled<F>) -> Self {
        Self::Second(*e)
    }
}
impl<F: FieldExt> Term<F> {
    pub fn compose(terms: &[Self], constant: F) -> Value<F> {
        terms.iter().fold(Value::known(constant), |acc, term| {
            acc.zip(term.value()).map(|(acc, coeff)| acc + coeff)
        })
    }
    pub fn is_empty(&self) -> bool {
        match self {
            Self::First(e) => e.is_empty(),
            Self::Second(e) => e.is_empty(),
            Self::Zero => true,
        }
    }
}
impl<F: FieldExt> Composable<F> for Term<F> {
    fn value(&self) -> Value<F> {
        match self {
            Self::First(e) => e.value(),
            Self::Second(e) => e.value(),
            Self::Zero => Value::known(F::zero()),
        }
    }
}
