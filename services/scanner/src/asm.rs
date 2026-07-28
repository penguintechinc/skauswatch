//! ASM (Application Security Monitoring) tool orchestration — Nuclei, ZAP, OpenVAS.
//! Phase 3 placeholder; minimal implementation for stream message flow.

/// Placeholder for ASM tool coordination.
/// Will implement Nuclei, ZAP, OpenVAS subprocess orchestration in Phase 3.
#[allow(dead_code)]
pub struct AsmOrchestrator {
    // Placeholder
}

#[allow(dead_code)]
impl AsmOrchestrator {
    /// Creates a new ASM orchestrator (Phase 3).
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for AsmOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_and_default_both_construct_the_placeholder() {
        // Phase 3 stub: Nuclei/ZAP/OpenVAS orchestration is not implemented
        // yet (see `crate::scan::execute_scan`'s "not yet implemented"
        // branch for those scan types) — this only proves the placeholder
        // type constructs via both paths, matching the trivial contract it
        // currently offers.
        let _ = AsmOrchestrator::new();
        let _ = AsmOrchestrator::default();
    }
}
