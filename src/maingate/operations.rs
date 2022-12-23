use crate::{Composable, Scaled, Term, Witness};
use halo2::{circuit::Value, halo2curves::FieldExt};
use num_integer::Integer;
use std::{collections::BTreeMap, fmt::Debug};

#[derive(Debug, Clone)]
pub enum Operation<F: FieldExt> {
    #[cfg(test)]
    AssertEqual {
        w0: Witness<F>,
        w1: Witness<F>,
    },
    #[cfg(test)]
    Assign {
        w: Witness<F>,
    },
    Add {
        w0: Witness<F>,
        w1: Witness<F>,
        u: Witness<F>,
    },
    AddScaled {
        w0: Scaled<F>,
        w1: Scaled<F>,
        u: Witness<F>,
    },
    Sub {
        w0: Witness<F>,
        w1: Witness<F>,
        u: Witness<F>,
    },
    Mul {
        w0: Witness<F>,
        w1: Witness<F>,
        u: Witness<F>,
    },
    Scale {
        w: Scaled<F>,
        u: Witness<F>,
    },
    DivUnsafe {
        w0: Witness<F>,
        w1: Witness<F>,
        u: Witness<F>,
    },
    InvUnsafe {
        w: Witness<F>,
        one: Witness<F>,
        u: Witness<F>,
    },
    AssertNotZero {
        w: Witness<F>,
        inv: Witness<F>,
        one: Witness<F>,
    },
    AssertBit {
        bit: Witness<F>,
    },
    AssertOneXorAny {
        bit: Witness<F>,
        one_xor_any: Witness<F>,
    },
    Or {
        w0: Witness<F>,
        w1: Witness<F>,
        u: Witness<F>,
    },
    AssertNand {
        w0: Witness<F>,
        w1: Witness<F>,
    },
}
#[derive(Debug, Clone)]
pub(crate) enum ConstantOperation<F: FieldExt> {
    AddConstant {
        w0: Witness<F>,
        constant: F,
        u: Witness<F>,
    },
    SubFromConstant {
        constant: F,
        w1: Witness<F>,
        u: Witness<F>,
    },
    SubAndAddConstant {
        w0: Witness<F>,
        w1: Witness<F>,
        constant: F,
        u: Witness<F>,
    },
    MulAddConstantScaled {
        factor: F,
        w0: Witness<F>,
        w1: Witness<F>,
        constant: F,
        u: Witness<F>,
    },
    EqualToConstant {
        w0: Witness<F>,
        constant: F,
    },
}
#[derive(Debug, Clone)]
pub(crate) enum ComplexOperation<F: FieldExt> {
    Select {
        cond: Witness<F>,
        w0: Witness<F>,
        w1: Witness<F>,
        selected: Witness<F>,
    },
    SelectOrAssign {
        cond: Witness<F>,
        w: Witness<F>,
        constant: F,
        selected: Witness<F>,
    },
    Compose {
        terms: Vec<Scaled<F>>,
        constant: F,
        result: Scaled<F>,
    },
    ComposeSecondDegree {
        terms: Vec<Term<F>>,
        constant: F,
        result: Scaled<F>,
    },
}
#[derive(Clone, Debug, Default)]
pub struct Collector<F: FieldExt> {
    pub(crate) number_of_witnesses: u32,
    pub(crate) simple_operations: Vec<Operation<F>>,
    pub(crate) constant_operations: Vec<ConstantOperation<F>>,
    pub(crate) complex_operations: Vec<ComplexOperation<F>>,
    pub(crate) copies: Vec<(u32, u32)>,
    pub(crate) constants: BTreeMap<F, Witness<F>>,
    bases: BTreeMap<usize, Vec<F>>,
    pub(crate) lookups: BTreeMap<usize, Vec<Witness<F>>>,
}
impl<F: FieldExt> Collector<F> {
    pub fn equal(&mut self, w0: &Witness<F>, w1: &Witness<F>) {
        self.copies.push((w0.id(), w1.id()))
    }
}
#[cfg(test)]
impl<F: FieldExt> Collector<F> {
    pub fn assign(&mut self, value: Value<F>) -> Witness<F> {
        let w = self.new_witness(value);
        self.simple_operations.push(Operation::Assign { w });
        w
    }
    pub fn assert_equal(&mut self, w0: &Witness<F>, w1: &Witness<F>) {
        self.simple_operations
            .push(Operation::AssertEqual { w0: *w0, w1: *w1 });
    }
}
impl<F: FieldExt> Collector<F> {
    pub fn register_constant(&mut self, constant: F) -> Witness<F> {
        match self.constants.get(&constant) {
            Some(constant) => *constant,
            _ => {
                let w = self.new_witness(Value::known(constant));
                self.equal_to_constant(&w, constant);
                w
            }
        }
    }
    pub fn get_constant(&mut self, constant: F) -> Witness<F> {
        self.register_constant(constant)
    }
}
impl<F: FieldExt> Collector<F> {
    pub(crate) fn new_witness(&mut self, value: Value<F>) -> Witness<F> {
        self.number_of_witnesses += 1;
        Witness {
            id: self.number_of_witnesses,
            value,
        }
    }
    pub(crate) fn bases(&mut self, bit_len: usize) -> Vec<F> {
        self.bases
            .entry(bit_len)
            .or_insert_with(|| {
                (0..F::NUM_BITS as usize / bit_len)
                    .map(|i| F::from(2).pow(&[(bit_len * i) as u64, 0, 0, 0]))
                    .collect()
            })
            .clone()
    }
    pub fn range(&mut self, w: &Witness<F>, bit_len: usize) {
        self.lookups
            .entry(bit_len)
            .and_modify(|witnesses| witnesses.push(*w))
            .or_insert_with(|| vec![*w]);
    }
    pub fn add(&mut self, w0: &Witness<F>, w1: &Witness<F>) -> Witness<F> {
        let u = w0.value() + w1.value();
        let u = self.new_witness(u);
        self.simple_operations.push(Operation::Add {
            w0: *w0,
            w1: *w1,
            u,
        });
        u
    }
    pub fn add_scaled(&mut self, w0: &Scaled<F>, w1: &Scaled<F>) -> Witness<F> {
        let u = w0.value() + w1.value();
        let u = self.new_witness(u);
        self.simple_operations.push(Operation::AddScaled {
            w0: *w0,
            w1: *w1,
            u,
        });
        u
    }
    pub fn sub(&mut self, w0: &Witness<F>, w1: &Witness<F>) -> Witness<F> {
        let u = w0.value() - w1.value();
        let u = self.new_witness(u);
        self.simple_operations.push(Operation::Sub {
            w0: *w0,
            w1: *w1,
            u,
        });
        u
    }
    pub fn mul(&mut self, w0: &Witness<F>, w1: &Witness<F>) -> Witness<F> {
        let u = w0.value() * w1.value();
        let u = self.new_witness(u);
        self.simple_operations.push(Operation::Mul {
            w0: *w0,
            w1: *w1,
            u,
        });
        u
    }
    pub fn scale(&mut self, w: Scaled<F>) -> Witness<F> {
        let u = w.value();
        let u = self.new_witness(u);
        self.simple_operations.push(Operation::Scale { w, u });
        u
    }
    pub fn div_unsafe(&mut self, w0: &Witness<F>, w1: &Witness<F>) -> Witness<F> {
        let u = w0
            .value()
            .zip(w1.value())
            .map(|(w0, w1)| w0 * w1.invert().unwrap());
        let u = self.new_witness(u);
        self.simple_operations.push(Operation::DivUnsafe {
            w0: *w0,
            w1: *w1,
            u,
        });
        u
    }
    pub fn inv_unsafe(&mut self, w: &Witness<F>) -> Witness<F> {
        let u = w.value().map(|w| w.invert().unwrap());
        let u = self.new_witness(u);
        let one = self.get_constant(F::one());
        self.simple_operations
            .push(Operation::InvUnsafe { w: *w, one, u });
        u
    }
    pub fn inv(&mut self, w: &Witness<F>) -> (Witness<F>, Witness<F>) {
        let (sign, inv) = w
            .value()
            .map(|w0| {
                Option::from(w0.invert())
                    .map(|inverted| (F::zero(), inverted))
                    .unwrap_or_else(|| (F::one(), F::one()))
            })
            .unzip();
        let sign = self.new_witness(sign);
        let inv = self.new_witness(inv);
        self.assert_bit(&sign);
        self.assert_one_xor_any(&sign, &inv);
        self.mul_add_constant_scaled(-F::one(), w, &inv, F::one());
        (inv, sign)
    }
    pub fn assert_not_zero(&mut self, w: &Witness<F>) {
        let inv: Value<F> = w.value().map(|a| {
            // With non inversion case valid proof cannot be produced
            a.invert().unwrap_or_else(F::zero)
        });
        let inv = self.new_witness(inv);
        let one = self.get_constant(F::one());
        self.simple_operations
            .push(Operation::AssertNotZero { w: *w, inv, one });
    }
    pub fn assert_not_equal(&mut self, w0: &Witness<F>, w1: &Witness<F>) {
        let u = self.sub(w0, w1);
        self.assert_not_zero(&u)
    }
    pub fn assert_bit(&mut self, bit: &Witness<F>) {
        self.simple_operations
            .push(Operation::AssertBit { bit: *bit });
    }
    pub fn assign_bit(&mut self, bit: Value<F>) -> Witness<F> {
        let bit = self.new_witness(bit);
        self.simple_operations.push(Operation::AssertBit { bit });
        bit
    }
    pub fn or(&mut self, w0: &Witness<F>, w1: &Witness<F>) -> Witness<F> {
        let u = w0.value() + w1.value() - w0.value() * w1.value();
        let u = self.new_witness(u);
        self.simple_operations.push(Operation::Or {
            w0: *w0,
            w1: *w1,
            u,
        });
        u
    }
    pub fn assert_one_xor_any(&mut self, bit: &Witness<F>, one_xor_any: &Witness<F>) {
        self.simple_operations.push(Operation::AssertOneXorAny {
            bit: *bit,
            one_xor_any: *one_xor_any,
        });
    }
    pub fn assert_nand(&mut self, w0: &Witness<F>, w1: &Witness<F>) {
        self.simple_operations
            .push(Operation::AssertNand { w0: *w0, w1: *w1 });
    }
    pub fn is_zero(&mut self, w0: &Witness<F>) -> Witness<F> {
        let (_, sign) = self.inv(w0);
        sign
    }
    pub fn is_equal(&mut self, w0: &Witness<F>, w1: &Witness<F>) -> Witness<F> {
        // 0 = (w0 - w1) * (r * (1 - x) + x) + r - 1
        let (x, r) = w0
            .value()
            .zip(w1.value())
            .map(|(w0, w1)| {
                let c = w0 - w1;
                Option::from(c.invert())
                    .map(|c_inverted| (c_inverted, F::zero()))
                    .unwrap_or_else(|| (F::one(), F::one()))
            })
            .unzip();
        let r0 = &self.assign_bit(r);
        let dif = &self.sub(w0, w1);
        let x = &self.new_witness(x);
        let u = &self.or(r0, x);
        let r1 = self.mul_add_constant_scaled(-F::one(), u, dif, F::one());
        self.equal(r0, &r1);
        r1
    }
    pub fn add_constant(&mut self, w0: &Witness<F>, constant: F) -> Witness<F> {
        let u = w0.value().map(|w0| w0 + constant);
        let u = self.new_witness(u);
        self.constant_operations
            .push(ConstantOperation::AddConstant {
                w0: *w0,
                constant,
                u,
            });
        u
    }
    pub fn sub_from_constant(&mut self, constant: F, w1: &Witness<F>) -> Witness<F> {
        let u = w1.value().map(|w1| constant - w1);
        let u = self.new_witness(u);
        self.constant_operations
            .push(ConstantOperation::SubFromConstant {
                constant,
                w1: *w1,
                u,
            });
        u
    }
    pub fn sub_and_add_constant(
        &mut self,
        w0: &Witness<F>,
        w1: &Witness<F>,
        constant: F,
    ) -> Witness<F> {
        let u = (w0.value() - w1.value).map(|dif| dif + constant);
        let u = self.new_witness(u);
        self.constant_operations
            .push(ConstantOperation::SubAndAddConstant {
                w0: *w0,
                w1: *w1,
                constant,
                u,
            });
        u
    }
    pub fn mul_add_constant_scaled(
        &mut self,
        factor: F,
        w0: &Witness<F>,
        w1: &Witness<F>,
        constant: F,
    ) -> Witness<F> {
        let u = (w0.value() * w1.value).map(|e| factor * e + constant);
        let u = self.new_witness(u);
        self.constant_operations
            .push(ConstantOperation::MulAddConstantScaled {
                factor,
                w0: *w0,
                w1: *w1,
                constant,
                u,
            });
        u
    }
    pub fn equal_to_constant(&mut self, w0: &Witness<F>, constant: F) {
        self.constant_operations
            .push(ConstantOperation::EqualToConstant { w0: *w0, constant })
    }
    pub fn assert_zero(&mut self, w0: &Witness<F>) {
        self.equal_to_constant(w0, F::zero())
    }
    pub fn assert_one(&mut self, w0: &Witness<F>) {
        self.equal_to_constant(w0, F::one())
    }
    pub fn select(&mut self, cond: &Witness<F>, w0: &Witness<F>, w1: &Witness<F>) -> Witness<F> {
        let selected = w0
            .value()
            .zip(w1.value())
            .zip(cond.value())
            .map(|((w0, w1), cond)| {
                if cond == F::one() {
                    w0
                } else {
                    #[cfg(feature = "sanity-check")]
                    {
                        assert_eq!(cond, F::zero());
                    }
                    w1
                }
            });
        let selected = self.new_witness(selected);
        self.complex_operations.push(ComplexOperation::Select {
            cond: *cond,
            w0: *w0,
            w1: *w1,
            selected,
        });
        selected
    }
    pub fn select_or_assign(
        &mut self,
        cond: &Witness<F>,
        w: &Witness<F>,
        constant: F,
    ) -> Witness<F> {
        let selected = w.value().zip(cond.value()).map(|(w, cond)| {
            if cond == F::one() {
                w
            } else {
                #[cfg(feature = "sanity-check")]
                {
                    assert_eq!(cond, F::zero());
                }
                constant
            }
        });
        let selected = self.new_witness(selected);
        self.complex_operations
            .push(ComplexOperation::SelectOrAssign {
                cond: *cond,
                w: *w,
                constant,
                selected,
            });
        selected
    }
    pub fn compose(&mut self, terms: &[Scaled<F>], constant: F, result_base: F) -> Witness<F> {
        let terms: Vec<Scaled<F>> = terms.iter().filter(|e| !e.is_empty()).cloned().collect();
        assert!(!terms.is_empty());
        let mut result = Scaled::compose(&terms[..], constant);
        let i_result_base: Option<F> = result_base.invert().into();
        result = result.map(|remaining| match i_result_base {
            Some(i_result_base) => i_result_base * remaining,
            _ => {
                #[cfg(feature = "sanity-check")]
                {
                    assert_eq!(remaining, F::zero());
                }
                F::zero()
            }
        });
        let result = self.new_witness(result);
        self.complex_operations.push(ComplexOperation::Compose {
            terms,
            constant,
            result: Scaled::new(&result.clone(), result_base),
        });
        result
    }
    pub fn compose_second_degree(
        &mut self,
        terms: &[Term<F>],
        constant: F,
        result_base: F,
    ) -> Witness<F> {
        let terms: Vec<Term<F>> = terms.iter().filter(|e| !e.is_empty()).cloned().collect();
        assert!(!terms.is_empty());
        let mut result = Term::compose(&terms[..], constant);
        let i_result_base: Option<F> = result_base.invert().into();
        result = result.map(|remaining| match i_result_base {
            Some(i_result_base) => i_result_base * remaining,
            _ => {
                #[cfg(feature = "sanity-check")]
                {
                    assert_eq!(remaining, F::zero());
                }
                F::zero()
            }
        });
        let result = self.new_witness(result);
        self.complex_operations
            .push(ComplexOperation::ComposeSecondDegree {
                terms,
                constant,
                result: Scaled::new(&result.clone(), result_base),
            });
        result
    }
}
impl<F: FieldExt> Collector<F> {
    pub fn decompose(
        &mut self,
        w0: &Witness<F>,
        sublimb_bit_len: usize,
        bit_len: usize,
    ) -> Vec<Witness<F>> {
        let (number_of_limbs, overflow_bit_len) = bit_len.div_rem(&sublimb_bit_len);
        let number_of_limbs = number_of_limbs + if overflow_bit_len > 0 { 1 } else { 0 };
        let decomposed = w0
            .decompose(number_of_limbs, sublimb_bit_len)
            .transpose_vec(number_of_limbs);
        let bases = self.bases(sublimb_bit_len)[..number_of_limbs].to_vec();
        let decomposed = decomposed
            .iter()
            .enumerate()
            .map(|(i, limb)| {
                let bit_len = if i == number_of_limbs - 1 && overflow_bit_len != 0 {
                    overflow_bit_len
                } else {
                    sublimb_bit_len
                };
                let w = self.new_witness(*limb);
                self.range(&w, bit_len);
                w
            })
            .collect::<Vec<Witness<F>>>();
        let terms: Vec<Scaled<_>> = decomposed
            .iter()
            .zip(bases.iter())
            .map(|(coeff, base)| Scaled::new(coeff, *base))
            .collect();
        let w1 = &self.compose(&terms[..], F::zero(), F::one());
        self.equal(w0, w1);
        decomposed
    }
    pub fn to_bits(&mut self, composed: &Witness<F>, number_of_bits: usize) -> Vec<Witness<F>> {
        assert!(number_of_bits <= F::NUM_BITS as usize);
        self.decompose(composed, 1, number_of_bits)
    }
}
