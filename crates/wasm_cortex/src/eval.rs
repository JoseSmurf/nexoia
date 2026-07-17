use crate::provenance::Provenance;

#[derive(Debug)]
pub struct RuntimeState {
    pub value: f32,
    pub strength: u8,
    pub provenance: Provenance,
}

pub fn calculate_contradiction_score(left: &RuntimeState, right: &RuntimeState) -> f32 {
    let mut score = 0.0;

    let diff = (left.value - right.value).abs();
    let max_val = left.value.max(right.value).max(1.0);
    score += (diff / max_val).min(1.0) * 0.6;

    let s_diff = (left.strength as f32 - right.strength as f32).abs() / 255.0;
    score += s_diff * 0.4;

    score.min(1.0)
}

pub fn trace_contradiction_source(left: &RuntimeState, right: &RuntimeState) -> Option<u64> {
    if left.strength < right.strength && left.provenance.count > 0 {
        Some(left.provenance.fragments[0])
    } else if right.provenance.count > 0 {
        Some(right.provenance.fragments[0])
    } else {
        None
    }
}
