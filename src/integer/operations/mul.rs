use crate::{
    integer::{
        chip::{IntegerChip, Range},
        ConstantInteger, Integer,
    },
    Scaled, SecondDegreeScaled, Term,
};
use halo2::halo2curves::FieldExt;

impl<
        'a,
        W: FieldExt,
        N: FieldExt,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
        const NUMBER_OF_SUBLIMBS: usize,
    > IntegerChip<'a, W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS>
{
    pub(crate) fn _mul(
        &mut self,
        w0: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        w1: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        #[cfg(test)]
        {
            self.report.n_mul += 1;
        }
        // find result and quotient witnesses
        let (result, quotient) = self.multiplication_witness(w0, w1);
        // range new witness integers
        let result = self.range(result, Range::Remainder);
        let quotient = self.range(quotient, Range::MulQuotient);
        // collect combination terms
        let modulus = self.rns.negative_wrong_modulus_decomposed;
        let terms = (0..NUMBER_OF_LIMBS)
            .collect::<Vec<usize>>()
            .chunks(2)
            .map(|indexes| {
                indexes
                    .iter()
                    .flat_map(|i| {
                        let base = self.rns.left_shifter(i % 2);
                        w0.limbs()
                            .iter()
                            .take(i + 1)
                            .zip(w1.limbs().iter().take(i + 1).rev())
                            .map(|(w0, w1)| {
                                SecondDegreeScaled::new(&w0.witness(), &w1.witness(), base).into()
                            })
                            .chain(
                                quotient
                                    .limbs()
                                    .iter()
                                    .take(i + 1)
                                    .zip(modulus.iter().take(i + 1).rev())
                                    .map(|(q, p)| Scaled::new(&q.witness(), base * p).into()),
                            )
                            .chain(vec![Scaled::new(result.limb(*i), -base).into()])
                            .collect::<Vec<Term<N>>>()
                    })
                    .collect::<Vec<Term<N>>>()
            })
            .collect::<Vec<Vec<Term<N>>>>();
        // find and range residues
        let mut carry: Term<N> = Term::Zero;
        let number_of_chunks = terms.len();
        for (i, terms) in terms.iter().enumerate() {
            let base = if i == number_of_chunks - 1 && NUMBER_OF_LIMBS % 2 == 1 {
                self.rns.left_shifter(1)
            } else {
                self.rns.left_shifter(2)
            };
            let terms = terms
                .iter()
                .chain(vec![&carry].into_iter())
                .cloned()
                .collect::<Vec<Term<N>>>();
            let residue = self.o.compose_second_degree(&terms[..], N::zero(), base);
            carry = Scaled::add(&residue).into();
            self.range_limb(&residue, self.rns.mul_v_bit_len);
        }
        // constrain native value
        let w0w1: Term<N> = SecondDegreeScaled::new(w0.native(), w1.native(), N::one()).into();
        let qp: Term<N> =
            Scaled::new(quotient.native(), -self.rns.wrong_modulus_in_native_modulus).into();
        let r = Scaled::new(result.native(), -N::one()).into();
        self.o
            .compose_second_degree(&[w0w1, qp, r], N::zero(), N::zero());

        result
    }
    pub(crate) fn _mul_constant(
        &mut self,
        w0: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        constant: &ConstantInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        #[cfg(test)]
        {
            self.report.n_mul_constant += 1;
        }
        // find result and quotient witnesses
        let (result, quotient) = self.constant_multiplication_witness(w0, constant);
        // range new witness integers
        let result = self.range(result, Range::Remainder);
        let quotient = self.range(quotient, Range::MulQuotient);
        // collect combination terms
        let modulus = self.rns.negative_wrong_modulus_decomposed;
        let terms = (0..NUMBER_OF_LIMBS)
            .collect::<Vec<usize>>()
            .chunks(2)
            .map(|indexes| {
                indexes
                    .iter()
                    .flat_map(|i| {
                        let base = self.rns.left_shifter(i % 2);
                        w0.limbs()
                            .iter()
                            .take(i + 1)
                            .zip(constant.limbs().iter().take(i + 1).rev())
                            .map(|(w0, w1)| Scaled::new(&w0.witness(), *w1 * base))
                            .chain(
                                quotient
                                    .limbs()
                                    .iter()
                                    .take(i + 1)
                                    .zip(modulus.iter().take(i + 1).rev())
                                    .map(|(q, p)| Scaled::new(&q.witness(), base * *p)),
                            )
                            .chain(vec![Scaled::new(result.limb(*i), -base)])
                            .collect::<Vec<Scaled<N>>>()
                    })
                    .collect::<Vec<Scaled<N>>>()
            })
            .collect::<Vec<Vec<Scaled<N>>>>();
        // find and range residues
        let number_of_chunks = terms.len();
        let mut carry: Scaled<N> = Scaled::dummy();
        for (i, terms) in terms.iter().enumerate() {
            let base = if i == number_of_chunks - 1 && NUMBER_OF_LIMBS % 2 == 1 {
                self.rns.left_shifter(1)
            } else {
                self.rns.left_shifter(2)
            };
            let terms = terms
                .iter()
                .chain(vec![&carry].into_iter())
                .cloned()
                .collect::<Vec<Scaled<N>>>();
            let residue = self.o.compose(&terms[..], N::zero(), base);
            carry = Scaled::add(&residue);
            self.range_limb(&residue, self.rns.mul_v_bit_len);
        }
        // constrain native value
        let w0w1 = Scaled::new(w0.native(), constant.native());
        let qp = Scaled::new(quotient.native(), -self.rns.wrong_modulus_in_native_modulus);
        let r = Scaled::new(result.native(), -N::one());
        self.o.compose(&[w0w1, qp, r], N::zero(), N::zero());

        result
    }
    pub(crate) fn _square(
        &mut self,
        w0: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        #[cfg(test)]
        {
            self.report.n_square += 1;
        }
        // t0 = a0a0
        // t1 = 2 * a0a1
        // t2 = 2 * a0a2 + a1a1
        // t3 = 2 * a0a3 + 2 * a1a2
        // t4 = 2 * a0a4 + 2 * a1a3 + a2a2
        // ...
        // find result and quotient witnesses
        let (result, quotient) = self.multiplication_witness(w0, w0);
        // range new witness integers
        let result = self.range(result, Range::Remainder);
        let quotient = self.range(quotient, Range::MulQuotient);
        // collect combination terms
        let modulus = self.rns.negative_wrong_modulus_decomposed;
        let terms = (0..NUMBER_OF_LIMBS)
            .collect::<Vec<usize>>()
            .chunks(2)
            .map(|indexes| {
                indexes
                    .iter()
                    .flat_map(|i| {
                        let base = self.rns.left_shifter(i % 2);
                        (0..=*i / 2)
                            .map(|j| {
                                let k = i - j;
                                SecondDegreeScaled::new(
                                    w0.limb(j),
                                    w0.limb(k),
                                    base * if j == k { N::one() } else { N::from(2) },
                                )
                                .into()
                            })
                            .chain(
                                quotient
                                    .limbs()
                                    .iter()
                                    .take(i + 1)
                                    .zip(modulus.iter().take(i + 1).rev())
                                    .map(|(q, p)| Scaled::new(&q.witness(), base * p).into()),
                            )
                            .chain(vec![Scaled::new(result.limb(*i), -base).into()])
                            .collect::<Vec<Term<N>>>()
                    })
                    .collect::<Vec<Term<N>>>()
            })
            .collect::<Vec<Vec<Term<N>>>>();
        // find and range residues
        let number_of_chunks = terms.len();
        let mut carry: Term<N> = Term::Zero;
        for (i, terms) in terms.iter().enumerate() {
            let base = if i == number_of_chunks - 1 && NUMBER_OF_LIMBS % 2 == 1 {
                self.rns.left_shifter(1)
            } else {
                self.rns.left_shifter(2)
            };
            let terms = terms
                .iter()
                .chain(vec![&carry].into_iter())
                .cloned()
                .collect::<Vec<Term<N>>>();
            let residue = self.o.compose_second_degree(&terms[..], N::zero(), base);
            carry = Scaled::add(&residue).into();
            self.range_limb(&residue, self.rns.mul_v_bit_len);
        }
        // constrain native value
        let w0w0: Term<N> = SecondDegreeScaled::new(w0.native(), w0.native(), N::one()).into();
        let qp: Term<N> =
            Scaled::new(quotient.native(), -self.rns.wrong_modulus_in_native_modulus).into();
        let r = Scaled::new(result.native(), -N::one()).into();
        self.o
            .compose_second_degree(&[w0w0, qp, r], N::zero(), N::zero());
        result
    }
    pub(crate) fn _div_incomplete(
        &mut self,
        w0: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        w1: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        // w0 / w1 = result
        // w0 = w1 * result
        // w0 + p * q = w1 * result
        #[cfg(test)]
        {
            self.report.n_div += 1;
        }
        // find result and quotient witnesses
        let (result, quotient) = self.division_witness(w0, w1);
        // range new witness integers
        let result = self.range(result, Range::Remainder);
        let quotient = self.range(quotient, Range::MulQuotient);
        // collect combination terms
        let modulus = self.rns.negative_wrong_modulus_decomposed;
        let terms = (0..NUMBER_OF_LIMBS)
            .collect::<Vec<usize>>()
            .chunks(2)
            .map(|indexes| {
                indexes
                    .iter()
                    .flat_map(|i| {
                        let base = self.rns.left_shifter(i % 2);
                        result
                            .limbs()
                            .iter()
                            .take(i + 1)
                            .zip(w1.limbs().iter().take(i + 1).rev())
                            .map(|(r, w1)| {
                                SecondDegreeScaled::new(&r.witness(), &w1.witness(), base).into()
                            })
                            .chain(
                                quotient
                                    .limbs()
                                    .iter()
                                    .take(i + 1)
                                    .zip(modulus.iter().take(i + 1).rev())
                                    .map(|(q, p)| Scaled::new(&q.witness(), base * p).into()),
                            )
                            .chain(vec![Scaled::new(w0.limb(*i), -base).into()])
                            .collect::<Vec<Term<N>>>()
                    })
                    .collect::<Vec<Term<N>>>()
            })
            .collect::<Vec<Vec<Term<N>>>>();
        // find and range residues
        let number_of_chunks = terms.len();
        let mut carry: Term<N> = Term::Zero;
        for (i, terms) in terms.iter().enumerate() {
            let base = if i == number_of_chunks - 1 && NUMBER_OF_LIMBS % 2 == 1 {
                self.rns.left_shifter(1)
            } else {
                self.rns.left_shifter(2)
            };
            let terms = terms
                .iter()
                .chain(vec![&carry].into_iter())
                .cloned()
                .collect::<Vec<Term<N>>>();
            let residue = self.o.compose_second_degree(&terms[..], N::zero(), base);
            carry = Scaled::add(&residue).into();
            self.range_limb(&residue, self.rns.mul_v_bit_len);
        }
        // constrain native value
        let w1_result: Term<N> =
            SecondDegreeScaled::new(result.native(), w1.native(), N::one()).into();
        let qp: Term<N> =
            Scaled::new(quotient.native(), -self.rns.wrong_modulus_in_native_modulus).into();
        let w0 = Scaled::new(w0.native(), -N::one()).into();
        self.o
            .compose_second_degree(&[w1_result, qp, w0], N::zero(), N::zero());

        result
    }
}
