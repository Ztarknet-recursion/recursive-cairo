use cairo_plonk_dsl_hints::CompositionQueryResult;
use circle_plonk_dsl_constraint_system::{
    var::{AllocVar, AllocationMode, Var},
    ConstraintSystemRef,
};
use circle_plonk_dsl_primitives::{option::OptionVar, M31Var, Poseidon2HalfVar, QM31Var};
use indexmap::IndexMap;
use stwo::core::fields::m31::M31;

use crate::utils::{ColumnsHasherQM31Var, HashAccumulatorQM31CompressedVar};

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

        let mut entry = HashAccumulatorQM31CompressedVar::new(&cs);

        let mut bits = vec![];
        for (k, _) in columns_hasher.map.iter() {
            let bit = log_size.is_eq(&M31Var::new_constant(&cs, &M31::from(*k)));
            bits.push(bit);
        }
        for ((_, v), bit) in columns_hasher.map.iter_mut().zip(bits.iter()) {
            entry = HashAccumulatorQM31CompressedVar::select(&entry, v, bit);
        }

        let mut decompressed = entry.decompress();
        decompressed.update(&self.0);
        let compressed = decompressed.compress();
        for ((_, v), bit) in columns_hasher.map.iter_mut().zip(bits.iter()) {
            *v = HashAccumulatorQM31CompressedVar::select(v, &compressed, bit);
        }

        columns_hasher.finalize()
    }
}
