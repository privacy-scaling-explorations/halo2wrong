use super::BaseFieldEccChip;
use crate::{
    ecc::{Point, Selector, Table, Windowed},
    Witness,
};
use group::ff::PrimeField;
use halo2::halo2curves::CurveAffine;
impl<
        C: CurveAffine,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
        const NUMBER_OF_SUBLIMBS: usize,
    > BaseFieldEccChip<C, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS>
{
    fn pad(&mut self, bits: &mut Vec<Witness<C::Scalar>>, window_size: usize) {
        use group::ff::Field;
        assert_eq!(bits.len(), C::Scalar::NUM_BITS as usize);
        // TODO: This is a tmp workaround. Instead of padding with zeros we can use a
        // shorter ending window.
        let padding_offset = (window_size - (bits.len() % window_size)) % window_size;
        let zeros: Vec<Witness<C::Scalar>> = (0..padding_offset)
            .map(|_| self.integer_chip.get_constant(C::Scalar::zero()))
            .collect();
        bits.extend(zeros);
        bits.reverse();
    }
    fn window(bits: Vec<Witness<C::Scalar>>, window_size: usize) -> Windowed<C::Scalar> {
        assert_eq!(bits.len() % window_size, 0);
        let number_of_windows = bits.len() / window_size;
        Windowed(
            (0..number_of_windows)
                .map(|i| {
                    let mut selector: Vec<Witness<C::Scalar>> = (0..window_size)
                        .map(|j| bits[i * window_size + j])
                        .collect();
                    selector.reverse();
                    Selector(selector)
                })
                .collect(),
        )
    }
    fn make_incremental_table(
        &mut self,
        aux: &Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        point: &Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        window_size: usize,
    ) -> Table<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let table_size = 1 << window_size;
        let mut table = vec![aux.clone()];
        for i in 0..(table_size - 1) {
            table.push(self.add(&table[i], point));
        }
        Table(table)
    }
    fn select_multi(
        &mut self,
        selector: &Selector<C::Scalar>,
        table: &Table<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let number_of_points = table.0.len();
        let number_of_selectors = selector.0.len();
        assert_eq!(number_of_points, 1 << number_of_selectors);
        let mut reducer = table.0.clone();
        for (i, selector) in selector.0.iter().enumerate() {
            let n = 1 << (number_of_selectors - 1 - i);
            for j in 0..n {
                let k = 2 * j;
                reducer[j] = self.select(selector, &reducer[k + 1], &reducer[k]);
            }
        }
        reducer[0].clone()
    }
    pub fn mul(
        &mut self,
        point: &Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        scalar: &Witness<C::Scalar>,
        window_size: usize,
    ) -> Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        assert!(window_size > 0);
        let aux = self.get_mul_aux(window_size, 1);
        let decomposed = &mut self.integer_chip.to_bits(scalar);
        self.pad(decomposed, window_size);
        let windowed = Self::window(decomposed.to_vec(), window_size);
        let table = &self.make_incremental_table(&aux.to_add, point, window_size);
        let mut acc = self.select_multi(&windowed.0[0], table);
        acc = self.double_n(&acc, window_size);
        let to_add = self.select_multi(&windowed.0[1], table);
        acc = self.add(&acc, &to_add);
        for selector in windowed.0.iter().skip(2) {
            acc = self.double_n(&acc, window_size - 1);
            let to_add = self.select_multi(selector, table);
            acc = self.ladder(&acc, &to_add);
        }
        self.add(&acc, &aux.to_sub)
    }
    #[allow(clippy::type_complexity)]
    pub fn mul_batch(
        &mut self,
        terms: Vec<(
            Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
            Witness<C::Scalar>,
        )>,
        window_size: usize,
    ) -> Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        self.mul_batch_1d_horizontal(terms, window_size)
    }
    #[allow(clippy::type_complexity)]
    fn mul_batch_1d_horizontal(
        &mut self,
        terms: Vec<(
            Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
            Witness<C::Scalar>,
        )>,
        window_size: usize,
    ) -> Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        assert!(window_size > 0);
        assert!(!terms.is_empty());
        let aux = self.get_mul_aux(window_size, terms.len());

        let mut decomposed_scalars: Vec<Vec<Witness<C::Scalar>>> = terms
            .iter()
            .map(|(_, scalar)| self.integer_chip.to_bits(scalar))
            .collect();
        for decomposed in decomposed_scalars.iter_mut() {
            self.pad(decomposed, window_size);
        }
        let windowed_scalars: Vec<Windowed<C::Scalar>> = decomposed_scalars
            .iter()
            .map(|decomposed| Self::window(decomposed.to_vec(), window_size))
            .collect();
        let number_of_windows = windowed_scalars[0].0.len();
        let mut binary_aux = aux.to_add.clone();
        let tables: Vec<Table<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>> = terms
            .iter()
            .enumerate()
            .map(|(i, (point, _))| {
                let table = self.make_incremental_table(&binary_aux, point, window_size);
                if i != terms.len() - 1 {
                    binary_aux = self.double(&binary_aux);
                }
                table
            })
            .collect();
        // preparation for the first round
        // initialize accumulator
        let mut acc = self.select_multi(&windowed_scalars[0].0[0], &tables[0]);
        // add first contributions other point scalar
        for (table, windowed) in tables.iter().skip(1).zip(windowed_scalars.iter().skip(1)) {
            let selector = &windowed.0[0];
            let to_add = self.select_multi(selector, table);
            acc = self.add(&acc, &to_add);
        }
        for i in 1..number_of_windows {
            acc = self.double_n(&acc, window_size);
            for (table, windowed) in tables.iter().zip(windowed_scalars.iter()) {
                let selector = &windowed.0[i];
                let to_add = self.select_multi(selector, table);
                acc = self.add(&acc, &to_add);
            }
        }
        self.add(&acc, &aux.to_sub)
    }
}
