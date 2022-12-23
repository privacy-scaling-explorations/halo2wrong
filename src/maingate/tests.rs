use super::{config::MainGate, operations::Collector, Gate};
use crate::{
    maingate::{
        config::ExtendedGate,
        operations::{ComplexOperation, ConstantOperation, Operation},
    },
    utils::compose,
    Composable, Scaled, SecondDegreeScaled, Term, Witness,
};
use halo2::{
    circuit::{floor_planner::V1, Layouter, Value},
    dev::MockProver,
    halo2curves::{pasta::Fp, FieldExt},
    plonk::{Circuit, ConstraintSystem, Error},
};
use rand::Rng;
use rand_core::OsRng;
use std::marker::PhantomData;

impl<F: FieldExt> Collector<F> {
    pub(crate) fn rand_witness(&mut self) -> Witness<F> {
        self.number_of_witnesses += 1;
        Witness {
            id: self.number_of_witnesses,
            value: Value::known(F::random(OsRng)),
        }
    }
    pub(crate) fn rand_scaled(&mut self) -> Scaled<F> {
        let witness = self.new_witness(Value::known(F::random(OsRng)));
        let factor = F::random(OsRng);
        Scaled::new(&witness, factor)
    }
    pub(crate) fn rand_second_degree_scaled(&mut self) -> SecondDegreeScaled<F> {
        self.number_of_witnesses += 1;
        let w0 = self.new_witness(Value::known(F::random(OsRng)));
        let w1 = self.new_witness(Value::known(F::random(OsRng)));
        let factor = F::random(OsRng);
        SecondDegreeScaled::new(&w0, &w1, factor)
    }
    pub(crate) fn rand_in_range(&mut self, bit_len: usize) -> Value<F> {
        let u: u64 = OsRng.gen();
        let u = F::from(u % (1 << bit_len));
        Value::known(u)
    }
    pub(crate) fn max_in_range(&mut self, bit_len: usize) -> Value<F> {
        let u = F::from((1 << bit_len) - 1);
        Value::known(u)
    }
}
#[derive(Clone)]
struct TestConfig1<F: FieldExt, G: Gate<F> + Clone> {
    gate: G,
    _marker: PhantomData<F>,
}
#[derive(Default)]
// struct MyCircuit1<F: FieldExt> {
struct MyCircuit1<F: FieldExt, G: Gate<F>> {
    _marker: PhantomData<(F, G)>,
}
impl<F: FieldExt, G: Gate<F> + Clone> Circuit<F> for MyCircuit1<F, G> {
    type Config = TestConfig1<F, G>;
    type FloorPlanner = V1;

    fn without_witnesses(&self) -> Self {
        Self {
            _marker: PhantomData,
        }
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        TestConfig1 {
            gate: G::configure(meta, vec![], vec![]),
            _marker: PhantomData,
        }
    }
    fn synthesize(&self, config: Self::Config, mut ly: impl Layouter<F>) -> Result<(), Error> {
        let mut o: Collector<F> = Collector::default();
        let ly = &mut ly;
        let value = |e: F| Value::known(e);
        let rand_fe = || F::random(OsRng);
        let rand_value = || value(rand_fe());
        let one = &o.register_constant(F::one());
        let zero = &o.register_constant(F::zero());
        o.assert_one(one);
        o.assert_zero(zero);
        o.assert_bit(one);
        o.assert_bit(zero);
        let rand_constant = rand_fe();
        // equality
        {
            let value = rand_value();
            let w0 = &o.assign(value);
            o.equal(w0, w0);
            o.assert_not_zero(w0);
            let w1 = &o.assign(value);
            o.equal(w1, w0);
            let w1 = &o.assign(rand_value());
            o.assert_not_equal(w0, w1);
        }
        // constant registry
        {
            let c0 = rand_fe();
            let w0 = &o.register_constant(c0);
            let w0_constant = &o.get_constant(c0);
            o.equal(w0_constant, w0);
            o.assert_equal(w0_constant, w0);
            o.equal_to_constant(w0, c0);
        }
        //arithmetic
        {
            let x0 = rand_fe();
            let x1 = rand_fe();
            let e0 = value(x0);
            let e1 = value(x1);
            let w0 = &o.assign(e0);
            let w1 = &o.assign(e1);
            // add
            let w0w1 = &o.add(w0, w1);
            let w1w0 = &o.add(w1, w0);
            o.equal(w0w1, w1w0);
            let must_be_w0w1 = &o.add_constant(w0, x1);
            o.equal(must_be_w0w1, w0w1);
            // sub
            let must_be_w0 = &o.sub(w0w1, w1);
            let must_be_w1 = &o.sub(w0w1, w0);
            o.equal(must_be_w0, w0);
            o.equal(must_be_w1, w1);
            let neg_w1 = &o.sub_from_constant(x0, w0w1);
            let must_be_zero = o.add(neg_w1, w1);
            o.assert_zero(&must_be_zero);
            let neg_w0 = &o.sub_from_constant(x1, w0w1);
            let must_be_zero = o.add(neg_w0, w0);
            o.assert_zero(&must_be_zero);
            let must_be_c = o.sub_and_add_constant(w0, w0, rand_constant);
            o.equal_to_constant(&must_be_c, rand_constant);
            // mul
            let w0w1 = &o.mul(w0, w1);
            let w1w0 = &o.mul(w1, w0);
            o.equal(w0w1, w1w0);
            Scaled::new(w0, x1);
            let must_be_w0w1 = &o.scale(Scaled::new(w0, x1));
            o.equal(must_be_w0w1, w0w1);
            let must_be_w0w1 = &o.scale(Scaled::new(w1, x0));
            o.equal(must_be_w0w1, w0w1);
            // div
            let must_be_w1 = &o.div_unsafe(w0w1, w0);
            o.equal(must_be_w1, w1);
            let must_be_w0 = &o.div_unsafe(w0w1, w1);
            o.equal(must_be_w0, w0);
            // inv
            let inv_w0 = &o.inv_unsafe(w0);
            let must_be_one = &o.mul(w0, inv_w0);
            o.assert_one(must_be_one);
            let (inv_w0, sign_must_be_zero) = &o.inv(w0);
            let must_be_one = &o.mul(w0, inv_w0);
            o.assert_one(must_be_one);
            o.assert_zero(sign_must_be_zero);
            let (result_must_be_one, sign_must_be_one) = &o.inv(zero);
            o.assert_one(sign_must_be_one);
            o.assert_one(result_must_be_one);
        }
        // bit assertation
        {
            // assigned
            o.assert_bit(one);
            o.assert_bit(zero);
            // unassigned
            let w0 = &o.new_witness(value(F::one()));
            o.assert_bit(w0);
            o.assert_one(w0);
            let w0 = &o.new_witness(value(F::zero()));
            o.assert_bit(w0);
            o.assert_zero(w0);
        }
        // selection
        {
            // select
            let e0 = rand_value();
            let w0 = &o.assign(e0);
            let e1 = rand_value();
            let w1 = &o.assign(e1);
            let selected = &o.select(one, w0, w1);
            o.equal(selected, w0);
            let selected = &o.select(zero, w0, w1);
            o.equal(selected, w1);
            // select or assign
            let e0 = rand_value();
            let w0 = &o.assign(e0);
            let constant = rand_fe();
            let selected = &o.select_or_assign(one, w0, constant);
            o.equal(selected, w0);
            let selected = &o.select_or_assign(zero, w0, constant);
            o.equal_to_constant(selected, constant);
        }
        // combination first degree
        for i in 1..30 {
            // assigned
            let terms: Vec<Scaled<F>> = (0..i)
                .map(|_| Scaled::new(&o.rand_witness(), rand_fe()))
                .collect();
            let constant = rand_fe();
            let result_base = rand_fe();
            let expected = Scaled::compose(&terms[..], constant);
            let expected = expected.map(|e| e * result_base.invert().unwrap());
            let result = o.compose(&terms[..], constant, result_base);
            result
                .value()
                .zip(expected)
                .map(|(e0, e1)| assert_eq!(e0, e1));
            // unassigned
            let terms: Vec<Scaled<F>> = (0..i)
                .map(|_| {
                    let w = &o.assign(rand_value());
                    Scaled::new(w, rand_fe())
                })
                .collect();
            let constant = rand_fe();
            let result_base = rand_fe();
            let expect = Scaled::compose(&terms[..], constant);
            let expect = expect.map(|e| e * result_base.invert().unwrap());
            let expect = &o.assign(expect);
            let result = o.compose(&terms[..], constant, result_base);
            result
                .value()
                .zip(expect.value())
                .map(|(e0, e1)| assert_eq!(e0, e1));
            // zerosum
            let mut terms: Vec<Scaled<F>> = (0..i)
                .map(|_| Scaled::new(&o.new_witness(rand_value()), rand_fe()))
                .collect();
            let constant = rand_fe();
            let result = Scaled::compose(&terms[..], constant);
            let result = o.assign(result);
            terms.push(Scaled::sub(&result));
            let result_base = F::zero();
            let result = &o.compose(&terms[..], constant, result_base);
            o.assert_zero(result)
        }
        // combination second degree
        for n in 0..30 {
            for m in 1..30 {
                let first_degree_terms: Vec<Term<F>> =
                    (0..n).map(|_| o.rand_scaled().into()).collect();
                let second_degree_terms: Vec<Term<F>> = (0..m)
                    .map(|_| o.rand_second_degree_scaled().into())
                    .collect();
                let terms: Vec<Term<F>> = first_degree_terms
                    .iter()
                    .chain(second_degree_terms.iter())
                    .cloned()
                    .collect();
                let constant = rand_fe();
                let result_base = rand_fe();
                let expect = Term::compose(&terms[..], constant);
                let expect = expect.map(|e| e * result_base.invert().unwrap());
                let expect = &o.assign(expect);
                let result = o.compose_second_degree(&terms[..], constant, result_base);
                result
                    .value()
                    .zip(expect.value())
                    .map(|(e0, e1)| assert_eq!(e0, e1));
                o.equal(&result, expect);
            }
        }
        // conditionals
        {
            let w0 = &o.rand_witness();
            let u = o.is_zero(w0);
            o.assert_zero(&u);
            let u = o.is_zero(zero);
            o.assert_one(&u);

            let w0 = &o.rand_witness();
            let must_be_w0 = &o.or(w0, zero);
            o.equal(must_be_w0, w0);
            let must_be_w0 = &o.or(zero, w0);
            o.equal(must_be_w0, w0);

            let w0 = &o.rand_witness();
            let w1 = &o.rand_witness();
            let must_be_one = o.is_equal(w0, w0);
            o.assert_one(&must_be_one);
            let must_be_zero = o.is_equal(w0, w1);
            o.assert_zero(&must_be_zero);
            let must_be_one = o.is_equal(zero, zero);
            o.assert_one(&must_be_one);
            let must_be_zero = o.is_equal(w0, zero);
            o.assert_zero(&must_be_zero);
        }
        #[cfg(feature = "info")]
        {
            o.info();
        }
        config.gate.layout(ly, &o)
    }
}
#[test]
fn test_arithmetic() {
    const K: u32 = 15;
    // extended gate
    let circuit = MyCircuit1::<Fp, ExtendedGate<_, 0>> {
        _marker: PhantomData::<_>,
    };
    let public_inputs = vec![vec![]];
    let prover = match MockProver::run(K, &circuit, public_inputs) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    prover.assert_satisfied();
    // main gate
    let circuit = MyCircuit1::<Fp, MainGate<_, 0>> {
        _marker: PhantomData::<_>,
    };
    let public_inputs = vec![vec![]];
    let prover = match MockProver::run(K, &circuit, public_inputs) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    prover.assert_satisfied();
}
impl<F: FieldExt, G: Gate<F>> MyCircuit2<F, G> {
    fn bit_lenghts() -> Vec<usize> {
        vec![4, 5, 6, 7]
    }
}
#[derive(Clone)]
struct TestConfig2<F: FieldExt, G: Gate<F> + Clone> {
    gate: G,
    _marker: PhantomData<F>,
}
#[derive(Default)]
struct MyCircuit2<F: FieldExt, G: Gate<F>> {
    _marker: PhantomData<(F, G)>,
}

impl<F: FieldExt, G: Gate<F> + Clone> Circuit<F> for MyCircuit2<F, G> {
    type Config = TestConfig2<F, G>;
    type FloorPlanner = V1;

    fn without_witnesses(&self) -> Self {
        Self {
            _marker: PhantomData,
        }
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        TestConfig2 {
            gate: G::configure(meta, Self::bit_lenghts(), vec![]),
            _marker: PhantomData,
        }
    }
    fn synthesize(&self, config: Self::Config, mut ly: impl Layouter<F>) -> Result<(), Error> {
        let mut o: Collector<F> = Collector::default();
        let ly = &mut ly;
        let bit_lenghts = Self::bit_lenghts();
        let max_vals = bit_lenghts
            .iter()
            .map(|b| {
                let max_val = o.max_in_range(*b);
                let max_val = o.assign(max_val);
                (*b, max_val)
            })
            .collect::<Vec<(usize, Witness<F>)>>();
        let random_vals: Vec<(usize, Witness<F>)> = bit_lenghts
            .iter()
            .map(|b| {
                (0..20)
                    .map(|_| {
                        let rand_val = o.rand_in_range(*b);
                        let rand_val = o.assign(rand_val);
                        (*b, rand_val)
                    })
                    .collect::<Vec<(usize, Witness<F>)>>()
            })
            .collect::<Vec<Vec<(usize, Witness<F>)>>>()
            .into_iter()
            .flatten()
            .collect();
        for (bit_len, w) in max_vals.iter().chain(random_vals.iter()) {
            o.range(w, *bit_len)
        }
        #[cfg(feature = "info")]
        {
            o.info();
        }
        config.gate.layout(ly, &o)?;
        Ok(())
    }
}
#[test]
fn test_lookup() {
    const K: u32 = 15;
    // extended gate
    let circuit = MyCircuit2::<Fp, ExtendedGate<_, 2>> {
        _marker: PhantomData::<_>,
    };
    let public_inputs = vec![vec![]];
    let prover = match MockProver::run(K, &circuit, public_inputs) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    prover.assert_satisfied();
    // main gate
    let circuit = MyCircuit2::<Fp, MainGate<_, 2>> {
        _marker: PhantomData::<_>,
    };
    let public_inputs = vec![vec![]];
    let prover = match MockProver::run(K, &circuit, public_inputs) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    prover.assert_satisfied();
}
#[derive(Clone)]
struct TestConfig3<F: FieldExt, G: Gate<F> + Clone> {
    gate: G,
    _marker: PhantomData<F>,
}
#[derive(Default)]
struct MyCircuit3<
    F: FieldExt,
    G: Gate<F> + Clone,
    const W: usize,
    const LIMB_BIT_LEN: usize,
    const OVERFLOW_BIT_LEN: usize,
> {
    _marker: PhantomData<(F, G)>,
}
impl<
        F: FieldExt,
        G: Gate<F> + Clone,
        const W: usize,
        const LIMB_BIT_LEN: usize,
        const OVERFLOW_BIT_LEN: usize,
    > Circuit<F> for MyCircuit3<F, G, W, LIMB_BIT_LEN, OVERFLOW_BIT_LEN>
{
    type Config = TestConfig3<F, G>;
    type FloorPlanner = V1;
    fn without_witnesses(&self) -> Self {
        Self {
            _marker: PhantomData,
        }
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        assert!(W > 0);
        TestConfig3 {
            gate: G::configure(meta, vec![LIMB_BIT_LEN, 1], vec![OVERFLOW_BIT_LEN]),
            _marker: PhantomData,
        }
    }
    fn synthesize(&self, config: Self::Config, mut ly: impl Layouter<F>) -> Result<(), Error> {
        let mut o: Collector<F> = Collector::default();
        let ly = &mut ly;
        // w/ overflow
        for number_of_limbs in 1..10 {
            let bit_len = number_of_limbs * LIMB_BIT_LEN + OVERFLOW_BIT_LEN;
            let v0 = o.max_in_range(bit_len);
            let w0 = o.assign(v0);
            let limbs = o.decompose(&w0, LIMB_BIT_LEN, bit_len);
            assert_eq!(limbs.len(), number_of_limbs  /* for overflow*/ + 1);

            for _ in 0..10 {
                let v0 = o.rand_in_range(bit_len);
                let w0 = o.assign(v0);
                let limbs = o.decompose(&w0, LIMB_BIT_LEN, bit_len);
                assert_eq!(limbs.len(), number_of_limbs  /* for overflow*/ + 1);
            }
        }
        // w/o overflow
        for number_of_limbs in 1..10 {
            let bit_len = number_of_limbs * LIMB_BIT_LEN;
            let v0 = o.max_in_range(bit_len);
            let w0 = o.assign(v0);
            let limbs = o.decompose(&w0, LIMB_BIT_LEN, bit_len);
            assert_eq!(limbs.len(), number_of_limbs);
            for _ in 0..10 {
                let v0 = o.rand_in_range(bit_len);
                let w0 = o.assign(v0);
                let limbs = o.decompose(&w0, LIMB_BIT_LEN, bit_len);
                assert_eq!(limbs.len(), number_of_limbs);
            }
        }
        // only overflow
        let bit_len = OVERFLOW_BIT_LEN;
        let v0 = o.max_in_range(bit_len);
        let w0 = &o.assign(v0);
        o.range(w0, OVERFLOW_BIT_LEN);
        for _ in 0..10 {
            let v0 = o.rand_in_range(bit_len);
            let w0 = &o.assign(v0);
            o.range(w0, OVERFLOW_BIT_LEN);
        }
        // only limb
        let bit_len = LIMB_BIT_LEN;
        let v0 = o.max_in_range(bit_len);
        let w0 = &o.assign(v0);
        o.range(w0, LIMB_BIT_LEN);
        for _ in 0..10 {
            let v0 = o.rand_in_range(bit_len);
            let w0 = &o.assign(v0);
            o.range(w0, LIMB_BIT_LEN);
        }
        // to bits
        let v0 = o.rand_witness().value();
        let w0 = &o.assign(v0);
        let n = F::NUM_BITS as usize;
        let decomposed = o.to_bits(w0, n);
        let bits: Vec<Value<F>> = decomposed.iter().map(|b| b.value()).collect();
        let bits: Value<Vec<F>> = Value::from_iter(bits);
        bits.zip(v0).map(|(bits, v0)| {
            let must_be_v0: F = compose(bits, 1);
            assert_eq!(must_be_v0, v0);
        });
        #[cfg(feature = "info")]
        {
            o.info();
        }
        config.gate.layout(ly, &o)?;
        Ok(())
    }
}
#[test]
fn test_decomposition() {
    const K: u32 = 15;
    // extended gate
    let circuit = MyCircuit1::<Fp, ExtendedGate<_, 2>> {
        _marker: PhantomData::<_>,
    };
    let public_inputs = vec![vec![]];
    let prover = match MockProver::run(K, &circuit, public_inputs) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    prover.assert_satisfied();
    // main gate
    let circuit = MyCircuit1::<Fp, MainGate<_, 2>> {
        _marker: PhantomData::<_>,
    };
    let public_inputs = vec![vec![]];
    let prover = match MockProver::run(K, &circuit, public_inputs) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    prover.assert_satisfied();
}

impl<F: FieldExt> Collector<F> {
    pub(crate) fn info(&self) {
        let mut add = 0;
        let mut add_scaled = 0;
        let mut sub = 0;
        let mut mul = 0;
        let mut scale = 0;
        let mut div_unsafe = 0;
        let mut inv_unsafe = 0;
        let mut assert_not_zero = 0;
        let mut assert_bit = 0;
        let mut assert_one_xor_any = 0;
        let mut or = 0;
        let mut assert_nand = 0;
        for op in self.simple_operations.iter() {
            match op {
                Operation::Add { w0: _, w1: _, u: _ } => add += 1,
                Operation::AddScaled { w0: _, w1: _, u: _ } => add_scaled += 1,
                Operation::Sub { w0: _, w1: _, u: _ } => sub += 1,
                Operation::Mul { w0: _, w1: _, u: _ } => mul += 1,
                Operation::Scale { w: _, u: _ } => scale += 1,
                Operation::DivUnsafe { w0: _, w1: _, u: _ } => div_unsafe += 1,
                Operation::InvUnsafe { w: _, one: _, u: _ } => inv_unsafe += 1,
                Operation::AssertNotZero {
                    w: _,
                    inv: _,
                    one: _,
                } => assert_not_zero += 1,
                Operation::AssertBit { bit: _ } => assert_bit += 1,
                Operation::AssertOneXorAny {
                    bit: _,
                    one_xor_any: _,
                } => assert_one_xor_any += 1,
                Operation::Or { w0: _, w1: _, u: _ } => or += 1,
                Operation::AssertNand { w0: _, w1: _ } => assert_nand += 1,
                _ => {}
            }
        }

        let mut add_constant = 0;
        let mut sub_from_constant = 0;
        let mut sub_and_add_constant = 0;
        let mut mul_add_constant_scaled = 0;
        let mut equal_to_constant = 0;
        for op in self.constant_operations.iter() {
            match op {
                ConstantOperation::AddConstant {
                    w0: _,
                    constant: _,
                    u: _,
                } => add_constant += 1,
                ConstantOperation::SubFromConstant {
                    constant: _,
                    w1: _,
                    u: _,
                } => sub_from_constant += 1,
                ConstantOperation::SubAndAddConstant {
                    w0: _,
                    w1: _,
                    constant: _,
                    u: _,
                } => sub_and_add_constant += 1,
                ConstantOperation::MulAddConstantScaled {
                    factor: _,
                    w0: _,
                    w1: _,
                    constant: _,
                    u: _,
                } => mul_add_constant_scaled += 1,
                ConstantOperation::EqualToConstant { w0: _, constant: _ } => equal_to_constant += 1,
            }
        }
        let mut select = 0;
        let mut select_or_assign = 0;
        let mut compose = 0;
        let mut compose_second_degree = 0;
        let mut compose_number_of_chunks = 0;
        let mut compose_second_degree_number_of_chunks = 0;
        for op in self.complex_operations.iter() {
            match op {
                ComplexOperation::Select {
                    cond: _,
                    w0: _,
                    w1: _,
                    selected: _,
                } => select += 1,
                ComplexOperation::SelectOrAssign {
                    cond: _,
                    w: _,
                    constant: _,
                    selected: _,
                } => select_or_assign += 1,
                ComplexOperation::Compose {
                    terms,
                    constant: _,
                    result: _,
                } => {
                    const CHUNK_SIZE: usize = 5;
                    let number_of_terms = terms.len();
                    let number_of_chunks = (number_of_terms - 1) / CHUNK_SIZE + 1;
                    compose_number_of_chunks += number_of_chunks;
                    compose += 1;
                }
                ComplexOperation::ComposeSecondDegree {
                    terms,
                    constant: _,
                    result: _,
                } => {
                    let number_of_second_degree_terms = terms
                        .iter()
                        .filter_map(|term| match term {
                            Term::Second(term) => Some(*term),
                            _ => None,
                        })
                        .count();
                    let number_of_sd_chunks = (number_of_second_degree_terms - 1) / 2 + 1;
                    compose_second_degree_number_of_chunks += number_of_sd_chunks;
                    compose_second_degree += 1;
                }
            }
        }

        println!("------");
        println!("collector {}", self.number_of_witnesses);
        println!("constants: {}", self.constants.len());
        println!("simple ops: {}", self.simple_operations.len());
        println!("constant ops: {}", self.constant_operations.len());
        println!("shorted ops: {}", self.complex_operations.len());

        println!("add: {}", add);
        println!("add_scaled: {}", add_scaled);
        println!("sub: {}", sub);
        println!("mul: {}", mul);
        println!("scale: {}", scale);
        println!("div_unsafe: {}", div_unsafe);
        println!("inv_unsafe: {}", inv_unsafe);
        println!("assert_not_zero: {}", assert_not_zero);
        println!("assert_bit: {}", assert_bit);
        println!("assert_one_xor_any: {}", assert_one_xor_any);
        println!("or: {}", or);
        println!("assert_nand: {}", assert_nand);
        println!("add_constant: {}", add_constant);
        println!("sub_from_constant: {}", sub_from_constant);
        println!("sub_and_add_constant: {}", sub_and_add_constant);
        println!("mul_add_constant_scaled: {}", mul_add_constant_scaled);
        println!("equal_to_constant: {}", equal_to_constant);
        println!("select: {}", select);
        println!("select_or_assign: {}", select_or_assign);
        println!("compose: {}", compose);
        println!("compose_second_degree: {}", compose_second_degree);
        println!("compose_number_of_chunks: {}", compose_number_of_chunks);
        println!(
            "compose_second_degree_number_of_chunks: {}",
            compose_second_degree_number_of_chunks
        );
        println!(
            "total compose chunks: {}",
            compose_number_of_chunks + compose_second_degree_number_of_chunks
        );
        let isolated = std::cmp::max(self.simple_operations.len(), self.constant_operations.len());
        let shorted = compose_number_of_chunks
            + compose_second_degree_number_of_chunks
            + select
            + select_or_assign;
        println!("isolated {}", isolated);
        println!("shorted {}", shorted);
        println!("total {}", shorted + isolated);

        println!("lookups");
        for (bitlen, limbs) in self.lookups.iter() {
            println!("{} {}", bitlen, limbs.len());
        }
        let number_of_lookus = self
            .lookups
            .iter()
            .fold(0usize, |acc, (_, next)| acc + next.len());
        println!("number of lookup {}", number_of_lookus);
    }
}
