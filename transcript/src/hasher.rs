use crate::{
    halo2::{arithmetic::FieldExt, plonk::Error},
    maingate::{AssignedValue, MainGate, MainGateConfig, MainGateInstructions, RegionCtx, Term},
};
use poseidon::{SparseMDSMatrix, Spec, State};

/// `AssignedState` is composed of `T` sized assigned values
#[derive(Debug, Clone)]
pub struct AssignedState<F: FieldExt, const T: usize>(pub(super) [AssignedValue<F>; T]);

/// `HasherChip` is basically responsible for contraining permutation part of
/// transcript pipeline
#[derive(Debug, Clone)]
pub(crate) struct HasherChip<
    F: FieldExt,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN: usize,
    const T: usize,
    const RATE: usize,
> {
    state: AssignedState<F, T>,
    absorbing: Vec<AssignedValue<F>>,
    spec: Spec<F, T, RATE>,
    main_gate_config: MainGateConfig,
}

impl<
        F: FieldExt,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN: usize,
        const T: usize,
        const RATE: usize,
    > HasherChip<F, NUMBER_OF_LIMBS, BIT_LEN, T, RATE>
{
    // Constructs new hasher chip with assigned initial state
    pub(crate) fn new(
        // TODO: we can remove initial state assingment in construction
        ctx: &mut RegionCtx<'_, '_, F>,
        spec: &Spec<F, T, RATE>,
        main_gate_config: &MainGateConfig,
    ) -> Result<Self, Error> {
        let main_gate = MainGate::<_>::new(main_gate_config.clone());

        let initial_state = State::<_, T>::default()
            .words()
            .iter()
            .map(|word| main_gate.assign_constant(ctx, *word))
            .collect::<Result<Vec<AssignedValue<F>>, Error>>()?;

        Ok(Self {
            state: AssignedState(initial_state.try_into().unwrap()),
            spec: spec.clone(),
            absorbing: vec![],
            main_gate_config: main_gate_config.clone(),
        })
    }

    /// Appends field elements to the absorbation line. It won't perform
    /// permutation here
    pub fn update(&mut self, elements: &[AssignedValue<F>]) {
        self.absorbing.extend_from_slice(elements);
    }
}

impl<
        F: FieldExt,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN: usize,
        const T: usize,
        const RATE: usize,
    > HasherChip<F, NUMBER_OF_LIMBS, BIT_LEN, T, RATE>
{
    /// Construct main gate
    pub(super) fn main_gate(&self) -> MainGate<F> {
        MainGate::<_>::new(self.main_gate_config.clone())
    }

    /*
        Internally expose poseidion parameters and matrices
    */

    pub(super) fn r_f_half(&self) -> usize {
        self.spec.r_f() / 2
    }

    pub(super) fn constants_start(&self) -> Vec<[F; T]> {
        self.spec.constants().start().clone()
    }

    pub(super) fn constants_partial(&self) -> Vec<F> {
        self.spec.constants().partial().clone()
    }

    pub(super) fn constants_end(&self) -> Vec<[F; T]> {
        self.spec.constants().end().clone()
    }

    pub(super) fn mds(&self) -> [[F; T]; T] {
        self.spec.mds_matrices().mds().rows()
    }

    pub(super) fn pre_sparse_mds(&self) -> [[F; T]; T] {
        self.spec.mds_matrices().pre_sparse_mds().rows()
    }

    pub(super) fn sparse_matrices(&self) -> Vec<SparseMDSMatrix<F, T, RATE>> {
        self.spec.mds_matrices().sparse_matrices().clone()
    }
}

impl<
        F: FieldExt,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN: usize,
        const T: usize,
        const RATE: usize,
    > HasherChip<F, NUMBER_OF_LIMBS, BIT_LEN, T, RATE>
{
    /// Applies full state sbox then adds constants to each word in the state
    fn sbox_full(
        &mut self,
        ctx: &mut RegionCtx<'_, '_, F>,
        constants: &[F; T],
    ) -> Result<(), Error> {
        let main_gate = self.main_gate();
        for (word, constant) in self.state.0.iter_mut().zip(constants.iter()) {
            let t = main_gate.mul(ctx, word, word)?;
            let t = main_gate.mul(ctx, &t, &t)?;
            *word = main_gate.mul_add_constant(ctx, &t, word, *constant)?;
        }
        Ok(())
    }

    /// Applies sbox to the first word then adds constants to each word in the
    /// state
    fn sbox_part(&mut self, ctx: &mut RegionCtx<'_, '_, F>, constant: F) -> Result<(), Error> {
        let main_gate = self.main_gate();
        let word = &mut self.state.0[0];
        let t = main_gate.mul(ctx, word, word)?;
        let t = main_gate.mul(ctx, &t, &t)?;
        *word = main_gate.mul_add_constant(ctx, &t, word, constant)?;

        Ok(())
    }

    // Adds pre constants and chunked inputs to the state.
    fn absorb_with_pre_constants(
        &mut self,
        ctx: &mut RegionCtx<'_, '_, F>,
        //
        // * inputs size equals to RATE: absorbing
        // * inputs size is less then RATE but not 0: padding
        // * inputs size is 0: extra permutation to avoid collution
        inputs: Vec<AssignedValue<F>>,
        pre_constants: &[F; T],
    ) -> Result<(), Error> {
        assert!(inputs.len() < T);
        let offset = inputs.len() + 1;
        let main_gate = self.main_gate();

        // Add the first constant to the first word
        self.state.0[0] = self
            .main_gate()
            .add_constant(ctx, &self.state.0[0], pre_constants[0])?;

        // Add inputs along with constants
        for ((word, constant), input) in self
            .state
            .0
            .iter_mut()
            .skip(1)
            .zip(pre_constants.iter().skip(1))
            .zip(inputs.iter())
        {
            *word = main_gate.add_with_constant(ctx, word, input, *constant)?;
        }

        // Padding
        for (i, (word, constant)) in self
            .state
            .0
            .iter_mut()
            .skip(offset)
            .zip(pre_constants.iter().skip(offset))
            .enumerate()
        {
            *word = main_gate.add_constant(
                ctx,
                word,
                if i == 0 {
                    // Mark
                    *constant + F::one()
                } else {
                    *constant
                },
            )?;
        }

        Ok(())
    }

    /// Applies MDS State multiplication
    fn apply_mds(
        &mut self,
        ctx: &mut RegionCtx<'_, '_, F>,
        mds: &[[F; T]; T],
    ) -> Result<(), Error> {
        // Calculate new state
        let new_state = mds
            .iter()
            .map(|row| {
                // term_i = s_0 * e_i_0 + s_1 * e_i_1 + ....
                let terms = self
                    .state
                    .0
                    .iter()
                    .zip(row.iter())
                    .map(|(e, word)| Term::Assigned(e.clone(), *word))
                    .collect::<Vec<Term<F>>>();

                self.main_gate().compose(ctx, &terms[..], F::zero())
            })
            .collect::<Result<Vec<AssignedValue<F>>, Error>>()?;

        // Assign new state
        for (word, new_word) in self.state.0.iter_mut().zip(new_state.into_iter()) {
            *word = new_word
        }

        Ok(())
    }

    /// Applies sparse MDS to the state
    fn apply_sparse_mds(
        &mut self,
        ctx: &mut RegionCtx<'_, '_, F>,
        mds: &SparseMDSMatrix<F, T, RATE>,
    ) -> Result<(), Error> {
        // For the 0th word
        let terms = self
            .state
            .0
            .iter()
            .zip(mds.row().iter())
            .map(|(e, word)| Term::Assigned(e.clone(), *word))
            .collect::<Vec<Term<F>>>();
        let mut new_state = vec![self.main_gate().compose(ctx, &terms[..], F::zero())?];

        // Rest of the trainsition ie the sparse part
        for (e, word) in mds.col_hat().iter().zip(self.state.0.iter().skip(1)) {
            new_state.push(self.main_gate().compose(
                ctx,
                &[
                    Term::Assigned(self.state.0[0].clone(), *e),
                    Term::Assigned(word.clone(), F::one()),
                ],
                F::zero(),
            )?);
        }

        // Assign new state
        for (word, new_word) in self.state.0.iter_mut().zip(new_state.into_iter()) {
            *word = new_word
        }

        Ok(())
    }

    /// Constrains poseidon permutation while mutating the given state
    pub(crate) fn permutation(
        &mut self,
        ctx: &mut RegionCtx<'_, '_, F>,
        inputs: Vec<AssignedValue<F>>,
    ) -> Result<(), Error> {
        let r_f = self.r_f_half();
        let mds = self.mds();
        let pre_sparse_mds = self.pre_sparse_mds();
        let sparse_matrices = self.sparse_matrices();

        // First half of the full rounds
        let constants = self.constants_start();
        self.absorb_with_pre_constants(ctx, inputs, &constants[0])?;
        for constants in constants.iter().skip(1).take(r_f - 1) {
            self.sbox_full(ctx, constants)?;
            self.apply_mds(ctx, &mds)?;
        }
        self.sbox_full(ctx, constants.last().unwrap())?;
        self.apply_mds(ctx, &pre_sparse_mds)?;

        // Partial rounds
        let constants = self.constants_partial();
        for (constant, sparse_mds) in constants.iter().zip(sparse_matrices.iter()) {
            self.sbox_part(ctx, *constant)?;
            self.apply_sparse_mds(ctx, sparse_mds)?;
        }

        // Second half of the full rounds
        let constants = self.constants_end();
        for constants in constants.iter() {
            self.sbox_full(ctx, constants)?;
            self.apply_mds(ctx, &mds)?;
        }
        self.sbox_full(ctx, &[F::zero(); T])?;
        self.apply_mds(ctx, &mds)?;

        Ok(())
    }

    pub(crate) fn hash(
        &mut self,
        ctx: &mut RegionCtx<'_, '_, F>,
    ) -> Result<AssignedValue<F>, Error> {
        // Get elements to be hashed
        let input_elements = self.absorbing.clone();
        // Flush the input que
        self.absorbing.clear();

        let mut padding_offset = 0;
        // Apply permutation to `RATE`Ï sized chunks
        for chunk in input_elements.chunks(RATE) {
            padding_offset = RATE - chunk.len();
            self.permutation(ctx, chunk.to_vec())?;
        }

        // If last chunking is full apply another permutation for collution resistance
        if padding_offset == 0 {
            self.permutation(ctx, vec![])?;
        }

        Ok(self.state.0[1].clone())
    }
}
