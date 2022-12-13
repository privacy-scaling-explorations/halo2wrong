use halo2::{
    halo2curves::FieldExt,
    plonk::{Advice, Column, ConstraintSystem, Fixed, Selector, TableColumn},
    poly::Rotation,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
};
#[derive(Clone, Debug)]
pub struct MainGate<F: FieldExt, const LOOKUP_WIDTH: usize> {
    // TODO: consider composition lenghts as `Range` const
    pub(crate) simple_gate: SimpleGate<F>,
    pub(crate) extended_gate: ExtendedGate<F>,
    pub(crate) q_isolate_simple: Selector,
    pub(crate) q_isolate_extended: Selector,
    pub(crate) q_short: Selector,
    pub(crate) lookup_gate: LookupGate<F, LOOKUP_WIDTH>,
}

#[derive(Clone, Debug)]
pub struct SimpleGate<F: FieldExt> {
    pub(crate) a: Column<Advice>,
    pub(crate) b: Column<Advice>,
    pub(crate) c: Column<Advice>,
    pub(crate) s_mul: Column<Fixed>,
    pub(crate) sa: Column<Fixed>,
    pub(crate) sb: Column<Fixed>,
    pub(crate) sc: Column<Fixed>,

    _marker: PhantomData<F>,
}

#[derive(Clone, Debug)]
pub struct ExtendedGate<F: FieldExt> {
    pub(crate) a: Column<Advice>,
    pub(crate) b: Column<Advice>,
    pub(crate) c: Column<Advice>,
    pub(crate) s_mul: Column<Fixed>,
    pub(crate) sa: Column<Fixed>,
    pub(crate) sb: Column<Fixed>,
    pub(crate) sc: Column<Fixed>,
    pub(crate) s_next: Column<Fixed>,
    pub(crate) constant: Column<Fixed>,
    // pub(crate) instance: Column<Instance>,
    _marker: PhantomData<F>,
}

impl<F: FieldExt, const LOOKUP_WIDTH: usize> MainGate<F, LOOKUP_WIDTH> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        composition_bit_lenghts: Vec<usize>,
        overflow_bit_lenghts: Vec<usize>,
    ) -> MainGate<F, LOOKUP_WIDTH> {
        let a0 = meta.advice_column();
        let b0 = meta.advice_column();
        let c0 = meta.advice_column();
        let sa0 = meta.fixed_column();
        let sb0 = meta.fixed_column();
        let sc0 = meta.fixed_column();
        let s_mul0 = meta.fixed_column();

        let a1 = meta.advice_column();
        let b1 = meta.advice_column();
        let c1 = meta.advice_column();
        let sa1 = meta.fixed_column();
        let sb1 = meta.fixed_column();
        let sc1 = meta.fixed_column();
        let s_mul1 = meta.fixed_column();

        let s_next = meta.fixed_column();
        let constant = meta.fixed_column();
        let instance = meta.instance_column();

        meta.enable_equality(a0);
        meta.enable_equality(b0);
        meta.enable_equality(c0);
        meta.enable_equality(a1);
        meta.enable_equality(b1);
        meta.enable_equality(c1);
        meta.enable_equality(instance);

        let q_isolate_simple = meta.selector();
        let q_isolate_extended = meta.selector();
        let q_short = meta.selector();

        meta.create_gate("maingate", |meta| {
            let a0 = meta.query_advice(a0, Rotation::cur());
            let b0 = meta.query_advice(b0, Rotation::cur());
            let c0 = meta.query_advice(c0, Rotation::cur());
            let a1 = meta.query_advice(a1, Rotation::cur());
            let b1 = meta.query_advice(b1, Rotation::cur());
            let next = meta.query_advice(c1, Rotation::next());
            let c1 = meta.query_advice(c1, Rotation::cur());

            let sa0 = meta.query_fixed(sa0, Rotation::cur());
            let sb0 = meta.query_fixed(sb0, Rotation::cur());
            let sc0 = meta.query_fixed(sc0, Rotation::cur());
            let sa1 = meta.query_fixed(sa1, Rotation::cur());
            let sb1 = meta.query_fixed(sb1, Rotation::cur());
            let sc1 = meta.query_fixed(sc1, Rotation::cur());
            let s_mul0 = meta.query_fixed(s_mul0, Rotation::cur());
            let s_mul1 = meta.query_fixed(s_mul1, Rotation::cur());
            let s_next = meta.query_fixed(s_next, Rotation::cur());
            let constant = meta.query_fixed(constant, Rotation::cur());
            let simple_gate = a0.clone() * sa0 + b0.clone() * sb0 + c0 * sc0 + a0 * b0 * s_mul0;
            let extended_gate = a1.clone() * sa1
                + b1.clone() * sb1
                + c1 * sc1
                + a1 * b1 * s_mul1
                + s_next * next
                + constant;

            let q_short = meta.query_selector(q_short);
            let q_isolate_simple = meta.query_selector(q_isolate_simple);
            let q_isolate_extended = meta.query_selector(q_isolate_extended);

            let isolated_simple_gate = q_isolate_simple * simple_gate.clone();
            let isolated_extended_gate = q_isolate_extended * extended_gate.clone();
            let shorted_gate = q_short * (simple_gate + extended_gate);

            vec![shorted_gate, isolated_simple_gate, isolated_extended_gate]
        });

        let extended_gate = ExtendedGate {
            a: a1,
            b: b1,
            c: c1,
            sa: sa1,
            sb: sb1,
            sc: sc1,
            s_mul: s_mul1,
            s_next,
            constant,
            // instance,
            _marker: PhantomData,
        };
        let simple_gate = SimpleGate {
            a: a0,
            b: b0,
            c: c0,
            sa: sa0,
            sb: sb0,
            sc: sc0,
            s_mul: s_mul0,
            _marker: PhantomData,
        };

        let mut bit_lengths: Vec<usize> = composition_bit_lenghts
            .iter()
            .chain(overflow_bit_lenghts.iter())
            .filter_map(|b| if *b == 0 { None } else { Some(*b) })
            .collect();
        bit_lengths.sort_unstable();
        bit_lengths.dedup();
        let lookup_gate = LookupGate::configure(meta, bit_lengths);

        MainGate {
            simple_gate,
            extended_gate,
            q_isolate_simple,
            q_isolate_extended,
            q_short,
            lookup_gate,
        }
    }
}
#[derive(Debug, Clone)]
pub struct LookupGate<F: FieldExt, const W: usize> {
    pub(super) bit_len_tag: BTreeMap<usize, usize>,
    pub(super) tag_table: TableColumn,
    pub(super) tag: Column<Fixed>,
    pub(super) value_table: TableColumn,
    pub(super) advice_columns: [Column<Advice>; W],
    pub(super) selector: Selector,
    _marker: PhantomData<F>,
}
impl<F: FieldExt, const W: usize> LookupGate<F, W> {
    pub fn configure(meta: &mut ConstraintSystem<F>, bit_lenghts: Vec<usize>) -> LookupGate<F, W> {
        let mut bit_lengths: Vec<usize> = bit_lenghts
            .iter()
            .filter_map(|b| if *b == 0 { None } else { Some(*b) })
            .collect();
        bit_lengths.sort_unstable();
        bit_lengths.dedup();
        let bit_len_tag = BTreeMap::from_iter(
            BTreeSet::from_iter(bit_lengths.iter())
                .into_iter()
                .enumerate()
                .map(|(idx, bit_len)| (*bit_len, idx + 1)),
        );
        let tag_table = meta.lookup_table_column();
        let value_table = meta.lookup_table_column();
        let tag = meta.fixed_column();
        let selector = meta.complex_selector();
        let advice_columns: Vec<Column<Advice>> = (0..W)
            .map(|_| {
                let column = meta.advice_column();
                meta.enable_equality(column);
                column
            })
            .collect();
        for advice_column in advice_columns.iter() {
            meta.lookup("lookup", |meta| {
                let selector = meta.query_selector(selector);
                let advice_column = meta.query_advice(*advice_column, Rotation::cur());
                let tag = meta.query_fixed(tag, Rotation::cur());
                vec![(tag, tag_table), (selector * advice_column, value_table)]
            });
        }
        // ???
        // meta.lookup("lookup", |meta| {
        //     let selector = meta.query_selector(selector);
        //     let mut expressions = vec![(meta.query_fixed(tag, Rotation::cur()), tag_table)];
        //     expressions.extend(advice_columns.iter().map(|advice_column| {
        //         let advice_column = meta.query_advice(*advice_column, Rotation::cur());
        //         (selector.clone() * advice_column, value_table)
        //     }));
        //     expressions
        // });
        LookupGate {
            bit_len_tag,
            tag_table,
            tag,
            value_table,
            advice_columns: advice_columns.try_into().unwrap(),
            selector,

            _marker: PhantomData,
        }
    }
}
