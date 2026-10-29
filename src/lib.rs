#![forbid(unsafe_code)]
#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::float_arithmetic,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const ORG_ID: u64 = 320_717_657_398;
pub const NOMINAL_GRID_FREQ_MHZ: i128 = 60_000;
pub const FREQ_DEADBAND_MHZ: i128 = 15;
pub const AAUFSA_TAX_RATE_BPS: i128 = 1_530;
pub const BPS_DENOMINATOR: i128 = 10_000;
pub const SMALL_BUSINESS_THRESHOLD_CENTS: i128 = 500_000_000;
pub const SAFE_HARBOR_MONTHS: u32 = 36;
pub const FTE_DISPLACEMENT_DAYS_THRESHOLD: u32 = 90;
pub const SOCIAL_SECURITY_ALLOCATION_BPS: i128 = 7_500;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CorporateDomain {
    AuraTetrax,
    Fourphonix,
    AuraIntelCore,
    AuraIntelGlobal,
    Standard1979,
    Prophonix,
}

impl CorporateDomain {
    #[must_use]
    pub const fn domain_id(self) -> u64 {
        match self {
            Self::AuraTetrax => 877_771_073_297,
            Self::Fourphonix => 964_521_086_569,
            Self::AuraIntelCore => 188_680_247_367,
            Self::AuraIntelGlobal => 1_087_754_464_927,
            Self::Standard1979 => 282_230_018_778,
            Self::Prophonix => 358_233_233,
        }
    }

    #[must_use]
    pub const fn canonical_hostname(self) -> &'static str {
        match self {
            Self::AuraTetrax => "AuraTetrax-com",
            Self::Fourphonix => "Fourphonix-com",
            Self::AuraIntelCore => "AuraIntelCore-com",
            Self::AuraIntelGlobal => "AuraIntel-Global-com",
            Self::Standard1979 => "Standard1979-com",
            Self::Prophonix => "Prophonix-com",
        }
    }

    #[must_use]
    pub const fn from_id(id: u64) -> Option<Self> {
        match id {
            877_771_073_297 => Some(Self::AuraTetrax),
            964_521_086_569 => Some(Self::Fourphonix),
            188_680_247_367 => Some(Self::AuraIntelCore),
            1_087_754_464_927 => Some(Self::AuraIntelGlobal),
            282_230_018_778 => Some(Self::Standard1979),
            358_233_233 => Some(Self::Prophonix),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CyberneticError {
    UnauthorizedDomain(u64),
    ArithmeticOverflow,
    VcpuQuotaExceeded { requested: u32, max_allowed: u32 },
    MemoryQuotaExceeded { requested_mib: u64, max_allowed_mib: u64 },
    IoBandwidthQuotaExceeded { requested_mbps: u64, max_allowed_mbps: u64 },
    ControlLoopLatencyViolation { measured_us: u64, max_allowed_us: u64 },
    AttestationVerificationFailed,
    SmtEnabledViolation,
    IommuDisabledViolation,
    InvalidPidGains,
    UnbalancedLedgerEntry { debit_cents: i128, credit_cents: i128 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VirtualSandboxQuota {
    pub domain: CorporateDomain,
    pub vm_instance_id: String,
    pub allocated_vcpus: u32,
    pub max_vcpus: u32,
    pub allocated_memory_mib: u64,
    pub max_memory_mib: u64,
    pub allocated_io_mbps: u64,
    pub max_io_mbps: u64,
    pub smt_disabled: bool,
    pub iommu_strict_pt: bool,
    pub vtpm_pcr_sha256: [u8; 32],
    pub expected_pcr_sha256: [u8; 32],
}

impl VirtualSandboxQuota {
    /// Verifica el aislamiento de vCPU, memoria, I/O, IOMMU, SMT y vTPM 2.0.
    ///
    /// # Errors
    /// Retorna `CyberneticError` si se incumple alguna cota de aislamiento.
    pub fn verify_isolation(&self) -> Result<(), CyberneticError> {
        if !self.smt_disabled {
            return Err(CyberneticError::SmtEnabledViolation);
        }
        if !self.iommu_strict_pt {
            return Err(CyberneticError::IommuDisabledViolation);
        }
        if self.vtpm_pcr_sha256 != self.expected_pcr_sha256 {
            return Err(CyberneticError::AttestationVerificationFailed);
        }
        if self.allocated_vcpus == 0 || self.allocated_vcpus > self.max_vcpus {
            return Err(CyberneticError::VcpuQuotaExceeded {
                requested: self.allocated_vcpus,
                max_allowed: self.max_vcpus,
            });
        }
        if self.allocated_memory_mib == 0 || self.allocated_memory_mib > self.max_memory_mib {
            return Err(CyberneticError::MemoryQuotaExceeded {
                requested_mib: self.allocated_memory_mib,
                max_allowed_mib: self.max_memory_mib,
            });
        }
        if self.allocated_io_mbps > self.max_io_mbps {
            return Err(CyberneticError::IoBandwidthQuotaExceeded {
                requested_mbps: self.allocated_io_mbps,
                max_allowed_mbps: self.max_io_mbps,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscretePidController {
    pub kp_scaled: i128,
    pub ki_scaled: i128,
    pub kd_scaled: i128,
    pub integral_accumulator: i128,
    pub previous_error_mhz: i128,
    pub max_integral_clamp: i128,
    pub max_dispatch_watts: i128,
    pub min_dispatch_watts: i128,
    pub max_loop_latency_us: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VppDispatchCommand {
    pub frequency_error_mhz: i128,
    pub power_dispatch_watts: i128,
    pub loop_latency_us: u64,
    pub fail_safe_engaged: bool,
}

impl DiscretePidController {
    /// Calcula el despacho de potencia en vatios usando aritmética entera determinista.
    ///
    /// # Errors
    /// Retorna `CyberneticError` si la latencia excede el límite o hay desbordamiento.
    pub fn compute_dispatch(
        &mut self,
        measured_freq_mhz: i128,
        measured_latency_us: u64,
    ) -> Result<VppDispatchCommand, CyberneticError> {
        if self.kp_scaled < 0 || self.ki_scaled < 0 || self.kd_scaled < 0 {
            return Err(CyberneticError::InvalidPidGains);
        }
        if measured_latency_us > self.max_loop_latency_us {
            return Err(CyberneticError::ControlLoopLatencyViolation {
                measured_us: measured_latency_us,
                max_allowed_us: self.max_loop_latency_us,
            });
        }

        let raw_error = NOMINAL_GRID_FREQ_MHZ
            .checked_sub(measured_freq_mhz)
            .ok_or(CyberneticError::ArithmeticOverflow)?;

        let effective_error = if raw_error.abs() <= FREQ_DEADBAND_MHZ {
            0
        } else {
            raw_error
        };

        let next_integral = self
            .integral_accumulator
            .checked_add(effective_error)
            .ok_or(CyberneticError::ArithmeticOverflow)?
            .clamp(
                self.max_integral_clamp
                    .checked_neg()
                    .ok_or(CyberneticError::ArithmeticOverflow)?,
                self.max_integral_clamp,
            );
        self.integral_accumulator = next_integral;

        let derivative = effective_error
            .checked_sub(self.previous_error_mhz)
            .ok_or(CyberneticError::ArithmeticOverflow)?;
        self.previous_error_mhz = effective_error;

        let p_term = self
            .kp_scaled
            .checked_mul(effective_error)
            .ok_or(CyberneticError::ArithmeticOverflow)?;
        let i_term = self
            .ki_scaled
            .checked_mul(self.integral_accumulator)
            .ok_or(CyberneticError::ArithmeticOverflow)?;
        let d_term = self
            .kd_scaled
            .checked_mul(derivative)
            .ok_or(CyberneticError::ArithmeticOverflow)?;

        let combined_scaled = p_term
            .checked_add(i_term)
            .and_then(|acc| acc.checked_add(d_term))
            .ok_or(CyberneticError::ArithmeticOverflow)?;

        let raw_watts = combined_scaled
            .checked_div(1_000)
            .ok_or(CyberneticError::ArithmeticOverflow)?;

        let clamped_watts = raw_watts.clamp(self.min_dispatch_watts, self.max_dispatch_watts);

        Ok(VppDispatchCommand {
            frequency_error_mhz: effective_error,
            power_dispatch_watts: clamped_watts,
            loop_latency_us: measured_latency_us,
            fail_safe_engaged: false,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AaufsaAssessmentInput {
    pub domain: CorporateDomain,
    pub end_user_ein: String,
    pub is_cloud_or_saas_provider: bool,
    pub displaced_fte_days: u32,
    pub displaced_human_wage_base_cents: i128,
    pub operating_cost_savings_cents: i128,
    pub aggregated_group_revenue_cents: i128,
    pub employee_reassigned_without_wage_reduction: bool,
    pub months_since_reassignment: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AaufsaTaxDetermination {
    pub taxable_base_cents: i128,
    pub total_excise_tax_cents: i128,
    pub social_security_trust_cents: i128,
    pub workforce_retraining_cents: i128,
    pub exemption_reason: Option<&'static str>,
    pub liable_party_ein: String,
}

/// Evalúa la obligación fiscal bajo el Capítulo 56 del IRC (`AAUFSA`).
///
/// # Errors
/// Retorna `CyberneticError::ArithmeticOverflow` si ocurre desbordamiento entero.
pub fn evaluate_aaufsa_liability(
    input: &AaufsaAssessmentInput,
) -> Result<AaufsaTaxDetermination, CyberneticError> {
    if input.is_cloud_or_saas_provider {
        return Ok(AaufsaTaxDetermination {
            taxable_base_cents: 0,
            total_excise_tax_cents: 0,
            social_security_trust_cents: 0,
            workforce_retraining_cents: 0,
            exemption_reason: Some("IRC_5000H_D_CLOUD_PROVIDER_EXEMPT_END_USER_LIABLE"),
            liable_party_ein: input.end_user_ein.clone(),
        });
    }

    if input.displaced_fte_days <= FTE_DISPLACEMENT_DAYS_THRESHOLD {
        return Ok(AaufsaTaxDetermination {
            taxable_base_cents: 0,
            total_excise_tax_cents: 0,
            social_security_trust_cents: 0,
            workforce_retraining_cents: 0,
            exemption_reason: Some("IRC_5000H_C_BELOW_90_DAY_DISPLACEMENT_THRESHOLD"),
            liable_party_ein: input.end_user_ein.clone(),
        });
    }

    if input.aggregated_group_revenue_cents < SMALL_BUSINESS_THRESHOLD_CENTS {
        return Ok(AaufsaTaxDetermination {
            taxable_base_cents: 0,
            total_excise_tax_cents: 0,
            social_security_trust_cents: 0,
            workforce_retraining_cents: 0,
            exemption_reason: Some("IRC_5000G_B_SMALL_BUSINESS_SAFE_HARBOR"),
            liable_party_ein: input.end_user_ein.clone(),
        });
    }

    if input.employee_reassigned_without_wage_reduction
        && input.months_since_reassignment <= SAFE_HARBOR_MONTHS
    {
        return Ok(AaufsaTaxDetermination {
            taxable_base_cents: 0,
            total_excise_tax_cents: 0,
            social_security_trust_cents: 0,
            workforce_retraining_cents: 0,
            exemption_reason: Some("IRC_5000G_A_36_MONTH_REASSIGNMENT_SAFE_HARBOR"),
            liable_party_ein: input.end_user_ein.clone(),
        });
    }

    let taxable_base_cents = input
        .displaced_human_wage_base_cents
        .max(input.operating_cost_savings_cents)
        .max(0);

    let total_excise_tax_cents = taxable_base_cents
        .checked_mul(AAUFSA_TAX_RATE_BPS)
        .and_then(|v| v.checked_div(BPS_DENOMINATOR))
        .ok_or(CyberneticError::ArithmeticOverflow)?;

    let social_security_trust_cents = total_excise_tax_cents
        .checked_mul(SOCIAL_SECURITY_ALLOCATION_BPS)
        .and_then(|v| v.checked_div(BPS_DENOMINATOR))
        .ok_or(CyberneticError::ArithmeticOverflow)?;

    let workforce_retraining_cents = total_excise_tax_cents
        .checked_sub(social_security_trust_cents)
        .ok_or(CyberneticError::ArithmeticOverflow)?;

    Ok(AaufsaTaxDetermination {
        taxable_base_cents,
        total_excise_tax_cents,
        social_security_trust_cents,
        workforce_retraining_cents,
        exemption_reason: None,
        liable_party_ein: input.end_user_ein.clone(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoubleEntryJournalRecord {
    pub org_id: u64,
    pub domain_id: u64,
    pub domain_hostname: &'static str,
    pub vm_instance_id: String,
    pub power_dispatch_watts: i128,
    pub debit_account: &'static str,
    pub credit_account_ss_trust: &'static str,
    pub credit_account_retraining: &'static str,
    pub debit_amount_cents: i128,
    pub credit_ss_trust_cents: i128,
    pub credit_retraining_cents: i128,
    pub previous_chain_hash_hex: String,
    pub record_sha256_hex: String,
}

impl DoubleEntryJournalRecord {
    /// Crea y sella con SHA-256 un asiento de partida doble.
    ///
    /// # Errors
    /// Retorna `CyberneticError` si los débitos y créditos no cuadran.
    pub fn create_sealed(
        quota: &VirtualSandboxQuota,
        dispatch: &VppDispatchCommand,
        tax: &AaufsaTaxDetermination,
        previous_chain_hash_hex: &str,
    ) -> Result<Self, CyberneticError> {
        let total_credits = tax
            .social_security_trust_cents
            .checked_add(tax.workforce_retraining_cents)
            .ok_or(CyberneticError::ArithmeticOverflow)?;

        if tax.total_excise_tax_cents != total_credits {
            return Err(CyberneticError::UnbalancedLedgerEntry {
                debit_cents: tax.total_excise_tax_cents,
                credit_cents: total_credits,
            });
        }

        let mut hasher = Sha256::new();
        hasher.update(ORG_ID.to_le_bytes());
        hasher.update(quota.domain.domain_id().to_le_bytes());
        hasher.update(quota.vm_instance_id.as_bytes());
        hasher.update(dispatch.power_dispatch_watts.to_le_bytes());
        hasher.update(tax.total_excise_tax_cents.to_le_bytes());
        hasher.update(tax.social_security_trust_cents.to_le_bytes());
        hasher.update(tax.workforce_retraining_cents.to_le_bytes());
        hasher.update(previous_chain_hash_hex.as_bytes());
        let digest = hasher.finalize();

        let mut hex_out = String::with_capacity(64);
        for byte in digest {
            use std::fmt::Write;
            let _ = write!(&mut hex_out, "{byte:02x}");
        }

        Ok(Self {
            org_id: ORG_ID,
            domain_id: quota.domain.domain_id(),
            domain_hostname: quota.domain.canonical_hostname(),
            vm_instance_id: quota.vm_instance_id.clone(),
            power_dispatch_watts: dispatch.power_dispatch_watts,
            debit_account: "5100-AAUFSA-AUTOMATION-EXCISE-EXPENSE",
            credit_account_ss_trust: "2410-IRS-CHAP56-SOCIAL-SECURITY-TRUST-75PCT",
            credit_account_retraining: "2420-IRS-CHAP56-WORKFORCE-RETRAINING-25PCT",
            debit_amount_cents: tax.total_excise_tax_cents,
            credit_ss_trust_cents: tax.social_security_trust_cents,
            credit_retraining_cents: tax.workforce_retraining_cents,
            previous_chain_hash_hex: previous_chain_hash_hex.to_owned(),
            record_sha256_hex: hex_out,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_six_corporate_domains_roundtrip() {
        let domains = [
            CorporateDomain::AuraTetrax,
            CorporateDomain::Fourphonix,
            CorporateDomain::AuraIntelCore,
            CorporateDomain::AuraIntelGlobal,
            CorporateDomain::Standard1979,
            CorporateDomain::Prophonix,
        ];
        for d in domains {
            let id = d.domain_id();
            assert_eq!(CorporateDomain::from_id(id), Some(d));
        }
        assert_eq!(CorporateDomain::from_id(999), None);
    }

    #[test]
    fn test_pid_deadband_and_response() {
        let mut pid = DiscretePidController {
            kp_scaled: 2_500,
            ki_scaled: 500,
            kd_scaled: 100,
            integral_accumulator: 0,
            previous_error_mhz: 0,
            max_integral_clamp: 50_000,
            max_dispatch_watts: 10_000_000,
            min_dispatch_watts: -10_000_000,
            max_loop_latency_us: 5_000,
        };

        let res_deadband = pid.compute_dispatch(59_990, 850);
        assert!(res_deadband.is_ok());
        if let Ok(cmd) = res_deadband {
            assert_eq!(cmd.power_dispatch_watts, 0);
        }

        let res_drop = pid.compute_dispatch(59_850, 920);
        assert!(res_drop.is_ok());
        if let Ok(cmd) = res_drop {
            assert_eq!(cmd.frequency_error_mhz, 150);
            assert_eq!(cmd.power_dispatch_watts, 465);
        }
    }

    #[test]
    fn test_aaufsa_tax_and_safe_harbors() {
        let active_input = AaufsaAssessmentInput {
            domain: CorporateDomain::AuraIntelGlobal,
            end_user_ein: String::from("98-7654321"),
            is_cloud_or_saas_provider: false,
            displaced_fte_days: 120,
            displaced_human_wage_base_cents: 100_000_000,
            operating_cost_savings_cents: 80_000_000,
            aggregated_group_revenue_cents: 900_000_000,
            employee_reassigned_without_wage_reduction: false,
            months_since_reassignment: 0,
        };
        let res = evaluate_aaufsa_liability(&active_input);
        assert!(res.is_ok());
        if let Ok(det) = res {
            assert_eq!(det.total_excise_tax_cents, 15_300_000);
            assert_eq!(det.social_security_trust_cents, 11_475_000);
            assert_eq!(det.workforce_retraining_cents, 3_825_000);
            assert!(det.exemption_reason.is_none());
        }

        let mut cloud_input = active_input.clone();
        cloud_input.is_cloud_or_saas_provider = true;
        let cloud_res = evaluate_aaufsa_liability(&cloud_input);
        assert!(cloud_res.is_ok());
        if let Ok(det) = cloud_res {
            assert_eq!(det.total_excise_tax_cents, 0);
            assert_eq!(
                det.exemption_reason,
                Some("IRC_5000H_D_CLOUD_PROVIDER_EXEMPT_END_USER_LIABLE")
            );
        }
    }
}
