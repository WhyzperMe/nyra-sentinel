//! Dependency-free, read-only-by-default SOC interface. No remote scripts or storage.
use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Redirect, Response},
};

pub async fn redirect() -> Redirect {
    Redirect::temporary("/ui")
}
fn asset(content_type: &'static str, body: &'static str, html: bool) -> Response {
    let csp = if html {
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    } else {
        "default-src 'none'; frame-ancestors 'none'"
    };
    let mut r = (StatusCode::OK, body).into_response();
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    h.insert("content-security-policy", HeaderValue::from_static(csp));
    h.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    h.insert("cache-control", HeaderValue::from_static("no-store"));
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    r
}
pub async fn index() -> Response {
    asset(
        "text/html; charset=utf-8",
        include_str!("../web/index.html"),
        true,
    )
}
pub async fn javascript() -> Response {
    asset(
        "text/javascript; charset=utf-8",
        include_str!("../web/app.js"),
        false,
    )
}
pub async fn stylesheet() -> Response {
    asset(
        "text/css; charset=utf-8",
        include_str!("../web/styles.css"),
        false,
    )
}
