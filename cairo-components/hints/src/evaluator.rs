use itertools::Itertools;
use stwo::core::{
    air::accumulation::PointEvaluationAccumulator,
    circle::CirclePoint,
    constraints::coset_vanishing,
    fields::{qm31::SecureField, FieldExpOps},
    pcs::TreeVec,
    poly::circle::CanonicCoset,
    ColumnVec,
};
use stwo_constraint_framework::{
    FrameworkComponent, FrameworkEval, PointEvaluator, PREPROCESSED_TRACE_IDX,
};

pub fn update_evaluation_accumulator<C: FrameworkEval>(
    evaluation_accumulator: &mut PointEvaluationAccumulator,
    component: &FrameworkComponent<C>,
    point: CirclePoint<SecureField>,
    mask: &TreeVec<ColumnVec<Vec<SecureField>>>,
) {
    let preprocessed_mask = (*component)
        .preprocessed_column_indices()
        .iter()
        .map(|idx| &mask[PREPROCESSED_TRACE_IDX][*idx])
        .collect_vec();

    let mut mask_points = mask.sub_tree(&(*component).trace_locations());
    mask_points[PREPROCESSED_TRACE_IDX] = preprocessed_mask;

    component.evaluate(PointEvaluator::new(
        mask_points,
        evaluation_accumulator,
        coset_vanishing(CanonicCoset::new((*component).log_size()).coset, point).inverse(),
        (*component).log_size(),
        (*component).claimed_sum(),
    ));
}
