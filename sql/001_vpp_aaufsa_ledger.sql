BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE;

CREATE TABLE IF NOT EXISTS corporate_domains (
    domain_id BIGINT PRIMARY KEY,
    org_id BIGINT NOT NULL CHECK (org_id = 320717657398),
    canonical_hostname VARCHAR(64) NOT NULL UNIQUE,
    jurisdiction_region VARCHAR(32) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_valid_corporate_domain CHECK (
        (domain_id = 877771073297  AND canonical_hostname = 'AuraTetrax-com') OR
        (domain_id = 964521086569  AND canonical_hostname = 'Fourphonix-com') OR
        (domain_id = 188680247367  AND canonical_hostname = 'AuraIntelCore-com') OR
        (domain_id = 1087754464927 AND canonical_hostname = 'AuraIntel-Global-com') OR
        (domain_id = 282230018778  AND canonical_hostname = 'Standard1979-com') OR
        (domain_id = 358233233     AND canonical_hostname = 'Prophonix-com')
    )
);

INSERT INTO corporate_domains (domain_id, org_id, canonical_hostname, jurisdiction_region) VALUES
    (877771073297,  320717657398, 'AuraTetrax-com',       'US-EAST-VA'),
    (964521086569,  320717657398, 'Fourphonix-com',       'US-WEST-OR'),
    (188680247367,  320717657398, 'AuraIntelCore-com',    'US-EAST-OH'),
    (1087754464927, 320717657398, 'AuraIntel-Global-com', 'EU-CENTRAL-DE'),
    (282230018778,  320717657398, 'Standard1979-com',     'US-CENTRAL-TX'),
    (358233233,     320717657398, 'Prophonix-com',        'MX-CENTRAL-QRO')
ON CONFLICT (domain_id) DO NOTHING;

CREATE TABLE IF NOT EXISTS cybernetic_vpp_aaufsa_ledger (
    entry_id BIGSERIAL PRIMARY KEY,
    org_id BIGINT NOT NULL DEFAULT 320717657398 CHECK (org_id = 320717657398),
    domain_id BIGINT NOT NULL REFERENCES corporate_domains(domain_id),
    vm_instance_id VARCHAR(128) NOT NULL,
    allocated_vcpus INTEGER NOT NULL CHECK (allocated_vcpus > 0 AND allocated_vcpus <= 256),
    allocated_memory_mib BIGINT NOT NULL CHECK (allocated_memory_mib > 0),
    smt_disabled BOOLEAN NOT NULL CHECK (smt_disabled = TRUE),
    iommu_strict_pt BOOLEAN NOT NULL CHECK (iommu_strict_pt = TRUE),
    vtpm_pcr_sha256 CHAR(64) NOT NULL,
    grid_frequency_error_mhz BIGINT NOT NULL,
    power_dispatch_watts BIGINT NOT NULL,
    control_loop_latency_us BIGINT NOT NULL CHECK (control_loop_latency_us >= 0 AND control_loop_latency_us <= 10000),
    end_user_ein VARCHAR(32) NOT NULL,
    is_cloud_provider_exempt BOOLEAN NOT NULL DEFAULT FALSE,
    aaufsa_exemption_code VARCHAR(64),
    taxable_base_cents BIGINT NOT NULL CHECK (taxable_base_cents >= 0),
    debit_excise_tax_cents BIGINT NOT NULL CHECK (debit_excise_tax_cents >= 0),
    credit_ss_trust_75pct_cents BIGINT NOT NULL CHECK (credit_ss_trust_75pct_cents >= 0),
    credit_retraining_25pct_cents BIGINT NOT NULL CHECK (credit_retraining_25pct_cents >= 0),
    prev_record_sha256 CHAR(64) NOT NULL,
    record_sha256 CHAR(64) NOT NULL UNIQUE,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_double_entry_balance CHECK (
        debit_excise_tax_cents = (credit_ss_trust_75pct_cents + credit_retraining_25pct_cents)
    ),
    CONSTRAINT chk_aaufsa_rate_or_exempt CHECK (
        (aaufsa_exemption_code IS NOT NULL AND debit_excise_tax_cents = 0) OR
        (aaufsa_exemption_code IS NULL AND debit_excise_tax_cents = (taxable_base_cents * 1530) / 10000)
    )
);

ALTER TABLE cybernetic_vpp_aaufsa_ledger ENABLE ROW LEVEL SECURITY;
ALTER TABLE cybernetic_vpp_aaufsa_ledger FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_domain_isolation_policy ON cybernetic_vpp_aaufsa_ledger;
CREATE POLICY tenant_domain_isolation_policy ON cybernetic_vpp_aaufsa_ledger
    USING (
        org_id = current_setting('app.current_org_id', true)::BIGINT
        AND domain_id = current_setting('app.current_domain_id', true)::BIGINT
    )
    WITH CHECK (
        org_id = current_setting('app.current_org_id', true)::BIGINT
        AND domain_id = current_setting('app.current_domain_id', true)::BIGINT
    );

CREATE OR REPLACE FUNCTION prevent_ledger_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'WORM_VIOLATION: cybernetic_vpp_aaufsa_ledger is append-only. UPDATE/DELETE prohibited.';
END;
$$;

DROP TRIGGER IF EXISTS trg_worm_cybernetic_ledger ON cybernetic_vpp_aaufsa_ledger;
CREATE TRIGGER trg_worm_cybernetic_ledger
    BEFORE UPDATE OR DELETE ON cybernetic_vpp_aaufsa_ledger
    FOR EACH ROW EXECUTE FUNCTION prevent_ledger_mutation();

COMMIT;
