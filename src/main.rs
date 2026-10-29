#![forbid(unsafe_code)]
#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::float_arithmetic
)]

use auraintel_vpp_cybernetic_governor::{
    evaluate_aaufsa_liability, AaufsaAssessmentInput, CorporateDomain, DiscretePidController,
    DoubleEntryJournalRecord, VirtualSandboxQuota,
};
use std::io::{self, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pcr_baseline: [u8; 32] = [0xAA; 32];

    let sandbox_quota = VirtualSandboxQuota {
        domain: CorporateDomain::AuraIntelGlobal,
        vm_instance_id: String::from("fc-microvm-vpp-node-0001"),
        allocated_vcpus: 4,
        max_vcpus: 8,
        allocated_memory_mib: 4096,
        max_memory_mib: 8192,
        allocated_io_mbps: 1000,
        max_io_mbps: 2500,
        smt_disabled: true,
        iommu_strict_pt: true,
        vtpm_pcr_sha256: pcr_baseline,
        expected_pcr_sha256: pcr_baseline,
    };

    sandbox_quota
        .verify_isolation()
        .map_err(|e| format!("Isolation check failed: {e:?}"))?;

    let mut pid_controller = DiscretePidController {
        kp_scaled: 3_000,
        ki_scaled: 600,
        kd_scaled: 150,
        integral_accumulator: 0,
        previous_error_mhz: 0,
        max_integral_clamp: 100_000,
        max_dispatch_watts: 25_000_000,
        min_dispatch_watts: -25_000_000,
        max_loop_latency_us: 2_000,
    };

    let dispatch_cmd = pid_controller
        .compute_dispatch(59_820, 410)
        .map_err(|e| format!("PID dispatch error: {e:?}"))?;

    let tax_input = AaufsaAssessmentInput {
        domain: CorporateDomain::AuraIntelGlobal,
        end_user_ein: String::from("12-3456789"),
        is_cloud_or_saas_provider: false,
        displaced_fte_days: 180,
        displaced_human_wage_base_cents: 250_000_000,
        operating_cost_savings_cents: 210_000_000,
        aggregated_group_revenue_cents: 1_500_000_000,
        employee_reassigned_without_wage_reduction: false,
        months_since_reassignment: 0,
    };

    let tax_determination = evaluate_aaufsa_liability(&tax_input)
        .map_err(|e| format!("AAUFSA tax evaluation failed: {e:?}"))?;

    let genesis_hash = "0000000000000000000000000000000000000000000000000000000000000000";
    let journal_record = DoubleEntryJournalRecord::create_sealed(
        &sandbox_quota,
        &dispatch_cmd,
        &tax_determination,
        genesis_hash,
    )
    .map_err(|e| format!("Ledger sealing error: {e:?}"))?;

    let serialized = serde_json::to_string_pretty(&journal_record)?;
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{serialized}")?;
    Ok(())
}
