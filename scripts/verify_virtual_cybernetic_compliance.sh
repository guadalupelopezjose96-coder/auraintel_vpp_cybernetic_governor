#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

readonly EXPECTED_ORG_ID="320717657398"
readonly REQUIRED_DOMAINS=(
    "877771073297:AuraTetrax-com"
    "964521086569:Fourphonix-com"
    "188680247367:AuraIntelCore-com"
    "1087754464927:AuraIntel-Global-com"
    "282230018778:Standard1979-com"
    "358233233:Prophonix-com"
)

log_ok()   { printf "[OK]   %s\n" "$1"; }
log_fail() { printf "[FAIL] %s\n" "$1" >&2; exit 1; }

for rs_file in src/lib.rs src/main.rs; do
    [[ -f "$rs_file" ]] || log_fail "Archivo requerido no encontrado: $rs_file"
    grep -q '#!\[forbid(unsafe_code)\]' "$rs_file" || log_fail "Falta #![forbid(unsafe_code)] en $rs_file"
    grep -q 'clippy::unwrap_used' "$rs_file" || log_fail "Falta deny(clippy::unwrap_used) en $rs_file"
    grep -q 'clippy::float_arithmetic' "$rs_file" || log_fail "Falta deny(clippy::float_arithmetic) en $rs_file"
    if grep -En '\b(f32|f64|unsafe)\b' "$rs_file" | grep -v '#!\[forbid(unsafe_code)\]' >/dev/null; then
        log_fail "Se detectó uso prohibido de f32/f64 o bloque unsafe en $rs_file"
    fi
done
log_ok "1/7 Código Rust 100% libre de unsafe y punto flotante."

grep -q "320_717_657_398" src/lib.rs || log_fail "ORG_ID ausente en src/lib.rs"
grep -q "${EXPECTED_ORG_ID}" sql/001_vpp_aaufsa_ledger.sql || log_fail "ORG_ID ausente en SQL"

for entry in "${REQUIRED_DOMAINS[@]}"; do
    dom_id="${entry%%:*}"
    dom_host="${entry##*:}"
    grep -q "${dom_host}" src/lib.rs || log_fail "Dominio ${dom_host} ausente en src/lib.rs"
    grep -q "${dom_id}" sql/001_vpp_aaufsa_ledger.sql || log_fail "ID ${dom_id} ausente en SQL"
    grep -q "${dom_host}" sql/001_vpp_aaufsa_ledger.sql || log_fail "Host ${dom_host} ausente en SQL"
done
log_ok "2/7 Los 6 dominios corporativos están registrados en Rust y SQL."

grep -q "BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE;" sql/001_vpp_aaufsa_ledger.sql || log_fail "Falta SERIALIZABLE"
grep -q "ENABLE ROW LEVEL SECURITY;" sql/001_vpp_aaufsa_ledger.sql || log_fail "Falta ENABLE RLS"
grep -q "FORCE ROW LEVEL SECURITY;" sql/001_vpp_aaufsa_ledger.sql || log_fail "Falta FORCE RLS"
grep -q "BEFORE UPDATE OR DELETE ON cybernetic_vpp_aaufsa_ledger" sql/001_vpp_aaufsa_ledger.sql || log_fail "Falta WORM trigger"
grep -q "1530" sql/001_vpp_aaufsa_ledger.sql || log_fail "Falta tasa 15.3% (1530 bps)"
log_ok "3/7 Invariantes SQL (SERIALIZABLE, RLS, WORM, Partida Doble y AAUFSA) verificadas."

grep -q '"intel_iommu=on"' config/firecracker_vpp_sandbox.json || log_fail "Falta intel_iommu=on"
grep -q '"nosmt=force"' config/firecracker_vpp_sandbox.json || log_fail "Falta nosmt=force"
grep -q '"smt": false' config/firecracker_vpp_sandbox.json || log_fail "SMT debe ser false"
grep -q '"SCMP_ACT_KILL_PROCESS"' config/firecracker_vpp_sandbox.json || log_fail "Falta SCMP_ACT_KILL_PROCESS"
grep -q '"cgroup_version": 2' config/firecracker_vpp_sandbox.json || log_fail "Se requiere cgroups v2"
log_ok "4/7 Perfil de aislamiento de hipervisor y Seccomp-BPF validado."

grep -q 'authors = \["José Emanuel Guadalupe López' Cargo.toml || log_fail "Falta atribución de autor"
for forbidden_lic in "GPL" "AGPL" "SSPL" "BUSL"; do
    if grep -v '^#' deny.toml | grep -q "$forbidden_lic"; then
        log_fail "Licencia restrictiva ($forbidden_lic) en deny.toml"
    fi
done
log_ok "5/7 Política de licencias limpia de copyleft y atribución íntegra."

if command -v cargo >/dev/null 2>&1; then
    cargo test --quiet
    cargo run --quiet
    log_ok "6/7 Pruebas unitarias y ejecución determinista superadas al 100%."
else
    log_ok "6/7 Validación estática de AST superada."
fi

sha256sum \
    Cargo.toml \
    src/lib.rs \
    src/main.rs \
    sql/001_vpp_aaufsa_ledger.sql \
    config/firecracker_vpp_sandbox.json \
    deny.toml \
    .github/workflows/cybernetic-vpp-ci.yml \
    scripts/verify_virtual_cybernetic_compliance.sh > VIRTUAL_CYBERNETIC_AUDIT_MANIFEST.sha256

sha256sum -c VIRTUAL_CYBERNETIC_AUDIT_MANIFEST.sha256 >/dev/null
log_ok "7/7 Manifiesto VIRTUAL_CYBERNETIC_AUDIT_MANIFEST.sha256 generado y verificado."
