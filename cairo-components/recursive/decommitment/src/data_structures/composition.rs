use cairo_plonk_dsl_hints::CompositionQueryResult;
use circle_plonk_dsl_constraint_system::{
    var::{AllocVar, AllocationMode, Var},
    ConstraintSystemRef,
};
use circle_plonk_dsl_primitives::{option::OptionVar, M31Var, Poseidon2HalfVar, QM31Var};
use indexmap::IndexMap;

use crate::utils::ColumnsHasherQM31Var;

pub struct CompositionQueryResultVar(pub [QM31Var; 2]);

impl Var for CompositionQueryResultVar {
    type Value = CompositionQueryResult;

    fn cs(&self) -> ConstraintSystemRef {
        self.0[0].cs()
    }
}

impl AllocVar for CompositionQueryResultVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        Self(std::array::from_fn(|i| {
            QM31Var::new_variables(cs, &value.0[i], mode)
        }))
    }
}

impl CompositionQueryResultVar {
    pub fn compute_column_hashes(
        &self,
        log_size: &M31Var,
    ) -> IndexMap<usize, OptionVar<Poseidon2HalfVar>> {
        let cs = self.0[0].cs();
        let mut columns_hasher = ColumnsHasherQM31Var::new(&cs);
        columns_hasher.update(&log_size, &self.0);
        columns_hasher.finalize()
    }
}
