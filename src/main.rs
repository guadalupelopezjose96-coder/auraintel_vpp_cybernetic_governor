#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic, clippy::unwrap_used)]

use actix_web::{
    http::header::{HeaderName, HeaderValue},
    middleware, web, App, HttpResponse, HttpServer, Responder,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::env;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;

pub const MAX_BUS_POWER_MILLIWATTS: i64 = 250_000_000; // 250,000 mW = 250 kW límite
pub const MAX_BESS_HEADROOM_KW: i64 = 500;
pub const TENANT_AURAINTELCORE: u64 = 188_680_247_367;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernorDispatchRequest {
    pub tenant_id: u64,
    pub solar_dispatch_kw: i64,
    pub bess_discharge_kw: i64,
    pub ev_charger_load_kw: i64,
    pub grid_lmp_price_usd_mwh: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernorDispatchResponse {
    pub timestamp_utc: String,
    pub net_active_power_kw: i64,
    pub total_bus_milliwatts: i64,
    pub breaker_status: &'static str,
    pub wholesale_revenue_usd_h: i64,
    pub saas_client_savings_usd_h: i64,
    pub status: &'static str,
}

pub struct GovernorMetrics {
    pub active_power_kw: AtomicI64,
    pub bess_headroom_kw: AtomicI64,
    pub breaker_closed: AtomicBool,
    pub market_price_usd_mwh: AtomicI64,
    pub wholesale_revenue_usd_h: AtomicI64,
    pub saas_savings_usd_h: AtomicI64,
}

pub struct AppState {
    pub metrics: Arc<GovernorMetrics>,
}

async fn dispatch_handler(
    req: web::Json<GovernorDispatchRequest>,
    data: web::Data<AppState>,
) -> impl Responder {
    if req.tenant_id != TENANT_AURAINTELCORE {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "UNAUTHORIZED_TENANT",
            "message": "Strict tenant isolation enforced for VPP Cybernetic Governor"
        }));
    }

    if req.solar_dispatch_kw < 0 || req.bess_discharge_kw < 0 || req.ev_charger_load_kw < 0 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "INVALID_TELEMETRY",
            "message": "Power dispatch values cannot be negative"
        }));
    }

    // Cálculo de potencia neta generada despachada a la red (kW)
    let net_active_power_kw = req.solar_dispatch_kw + req.bess_discharge_kw - req.ev_charger_load_kw;
    let total_bus_milliwatts = net_active_power_kw * 1_000_000;

    // Regla de protección de subestación IEC 61850 XCBR1
    let (breaker_status, dispatch_status) = if total_bus_milliwatts > MAX_BUS_POWER_MILLIWATTS {
        data.metrics.breaker_closed.store(false, Ordering::SeqCst);
        ("OPEN (TRIP)", "OVERCURRENT_PROTECTION_TRIGGERED")
    } else {
        data.metrics.breaker_closed.store(true, Ordering::SeqCst);
        ("CLOSED (OK)", "DISPATCH_OPTIMAL_STABLE")
    };

    // Arbitraje Front-of-the-Meter y Ahorro Behind-the-Meter (en USD enteros por hora)
    let wholesale_revenue = (net_active_power_kw * req.grid_lmp_price_usd_mwh) / 1000;
    let saas_savings = (req.solar_dispatch_kw * 120) / 1000; // Benchmark $120/MWh ahorro base

    // Actualizar métricas atómicas
    data.metrics.active_power_kw.store(net_active_power_kw, Ordering::Relaxed);
    data.metrics.market_price_usd_mwh.store(req.grid_lmp_price_usd_mwh, Ordering::Relaxed);
    data.metrics.wholesale_revenue_usd_h.store(wholesale_revenue, Ordering::Relaxed);
    data.metrics.saas_savings_usd_h.store(saas_savings, Ordering::Relaxed);

    HttpResponse::Ok().json(GovernorDispatchResponse {
        timestamp_utc: Utc::now().to_rfc3339(),
        net_active_power_kw,
        total_bus_milliwatts,
        breaker_status,
        wholesale_revenue_usd_h: wholesale_revenue,
        saas_client_savings_usd_h: saas_savings,
        status: dispatch_status,
    })
}

async fn prometheus_metrics_handler(data: web::Data<AppState>) -> impl Responder {
    let active_power = data.metrics.active_power_kw.load(Ordering::Relaxed);
    let bess_headroom = data.metrics.bess_headroom_kw.load(Ordering::Relaxed);
    let breaker_val = if data.metrics.breaker_closed.load(Ordering::Relaxed) { 1 } else { 0 };
    let market_price = data.metrics.market_price_usd_mwh.load(Ordering::Relaxed);
    let wholesale_rev = data.metrics.wholesale_revenue_usd_h.load(Ordering::Relaxed);
    let saas_savings = data.metrics.saas_savings_usd_h.load(Ordering::Relaxed);

    let metrics_payload = format!(
        "# HELP vpp_active_power_kw Potencia activa total despachada a la red (kW)\n\
         # TYPE vpp_active_power_kw gauge\n\
         vpp_active_power_kw {}\n\
         # HELP vpp_bess_discharge_headroom_kw Reserva disponible en baterias BESS (kW)\n\
         # TYPE vpp_bess_discharge_headroom_kw gauge\n\
         vpp_bess_discharge_headroom_kw {}\n\
         # HELP vpp_breaker_status Estado disyuntor subestacion XCBR1 (1=CLOSED, 0=TRIP)\n\
         # TYPE vpp_breaker_status gauge\n\
         vpp_breaker_status {}\n\
         # HELP vpp_market_price_usd_mwh Precio Spot Mercado Mayorista LMP\n\
         # TYPE vpp_market_price_usd_mwh gauge\n\
         vpp_market_price_usd_mwh {}\n\
         # HELP vpp_wholesale_revenue_usd_h Ingresos en vivo mercado mayorista (USD/h)\n\
         # TYPE vpp_wholesale_revenue_usd_h gauge\n\
         vpp_wholesale_revenue_usd_h {}\n\
         # HELP vpp_saas_client_savings_usd_h Ahorro en vivo cliente industrial SaaS (USD/h)\n\
         # TYPE vpp_saas_client_savings_usd_h gauge\n\
         vpp_saas_client_savings_usd_h {}\n",
        active_power, bess_headroom, breaker_val, market_price, wholesale_rev, saas_savings
    );

    HttpResponse::Ok()
        .content_type("text/plain; version=0.0.4; charset=utf-8")
        .body(metrics_payload)
}

async fn health_handler() -> impl Responder {
    let mut res = HttpResponse::Ok();
    res.insert_header((
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    ));
    res.insert_header((
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    ));
    res.json(serde_json::json!({
        "module": "auraintel_vpp_cybernetic_governor",
        "version": "1.0.0",
        "tenant_id": TENANT_AURAINTELCORE,
        "max_bus_power_milliwatts": MAX_BUS_POWER_MILLIWATTS,
        "iec_61850_governance": "ACTIVE",
        "prometheus_exporter": "/metrics"
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let port_str = env::var("PORT").unwrap_or_else(|_| String::from("8083"));
    let port: u16 = port_str.parse().unwrap_or(8083);
    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    let metrics_state = web::Data::new(AppState {
        metrics: Arc::new(GovernorMetrics {
            active_power_kw: AtomicI64::new(150),
            bess_headroom_kw: AtomicI64::new(350),
            breaker_closed: AtomicBool::new(true),
            market_price_usd_mwh: AtomicI64::new(65),
            wholesale_revenue_usd_h: AtomicI64::new(98),
            saas_savings_usd_h: AtomicI64::new(145),
        }),
    });

    println!("AuraIntel VPP Cybernetic Governor activo en http://127.0.0.1:{}", port);

    HttpServer::new(move || {
        App::new()
            .app_data(metrics_state.clone())
            .wrap(middleware::Compress::default())
            .wrap(middleware::Logger::default())
            .route("/api/v1/vpp/dispatch", web::post().to(dispatch_handler))
            .route("/metrics", web::get().to(prometheus_metrics_handler))
            .route("/health", web::get().to(health_handler))
    })
    .bind(addr)?
    .run()
    .await
}
