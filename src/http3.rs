use anyhow::Context;
use anyhow::Result;
use bytes::Buf;
use bytes::Bytes;
use h3::quic::BidiStream;
use h3::server::RequestResolver;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use hyper::Request;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use konfig::{HttpMethod, ProxyError, ProxyState};
use std::sync::Arc;
use tokio::sync::mpsc;

pub type HttpClient =
    Client<HttpConnector, http_body_util::combinators::BoxBody<Bytes, std::io::Error>>;

/// Returns true for HTTP/1.1 hop-by-hop headers that must not be
/// forwarded over HTTP/3 in either direction.
fn is_hop_by_hop(name: &hyper::header::HeaderName) -> bool {
    matches!(
        name.as_str(),
        "transfer-encoding"
            | "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "upgrade"
    )
}

/// Returns true for headers that must not be sent to the HTTP/1.1 backend.
/// Covers hop-by-hop headers plus `host` (hyper derives it from the URI).
fn is_forbidden_request_header(name: &hyper::header::HeaderName) -> bool {
    is_hop_by_hop(name) || name.as_str() == "host"
}

pub async fn process_h3_request<C>(
    resolver: RequestResolver<C, Bytes>,
    client: HttpClient,
    _backend_addr: &str,
    proxy_state: Arc<ProxyState>,
) -> Result<String>
where
    C: h3::quic::Connection<Bytes> + 'static,
    <C as h3::quic::OpenStreams<Bytes>>::BidiStream: BidiStream<Bytes> + Send + 'static,
    <<C as h3::quic::OpenStreams<Bytes>>::BidiStream as BidiStream<Bytes>>::RecvStream:
        Send + Sync + 'static,
    <<C as h3::quic::OpenStreams<Bytes>>::BidiStream as BidiStream<Bytes>>::SendStream:
        Send + Sync + 'static,
{
    // ── 1. Resolve the incoming request ──────────────────────────────────────
    let (req, stream) = resolver.resolve_request().await?;

    let method = req.method().clone();
    let uri_path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_default();
    let req_headers = req.headers().clone();

    tracing::debug!("h3 request: {} {} headers={:?}", method, req.uri(), req_headers);

    // ── 2. Extract domain and validate via konfig ────────────────────────────
    let domain = req_headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_string();

    tracing::debug!("domain lookup: host header = {:?}, extracted domain = {:?}", req_headers.get("host"), domain);

    // Look up organization by domain
    let org = match proxy_state.lookup_org(&domain).await {
        Some(org) => org,
        None => {
            let org_index = proxy_state.org_index.read().await;
            let available_domains: Vec<&str> = org_index.keys().map(|s| s.as_str()).collect();
            tracing::debug!("domain lookup failed for '{}', available domains: {:?}", domain, available_domains);
            // No org found for this domain — return 404
            let (mut send_stream, _recv_stream) = stream.split();
            let resp = http::Response::builder()
                .status(404)
                .body(())
                .unwrap();
            send_stream.send_response(resp).await.ok();
            send_stream.finish().await.ok();
            return Ok(format!("rejected: no organization for domain {domain}"));
        }
    };

    // Extract token from cookie
    let cookie_name = &org.auth.cookie_name;
    let token = req_headers
        .get("cookie")
        .and_then(|val| val.to_str().ok())
        .and_then(|cookie_str| konfig::parse_cookie(cookie_str, cookie_name));

    let token = match token {
        Some(t) if !t.is_empty() => t,
        _ => {
            let (mut send_stream, _recv_stream) = stream.split();
            let resp = http::Response::builder()
                .status(401)
                .body(())
                .unwrap();
            send_stream.send_response(resp).await.ok();
            send_stream.finish().await.ok();
            return Ok(format!("rejected: missing token cookie for domain {domain}"));
        }
    };

    // Validate JWT
    let claims = match konfig::validate_jwt(&token, &org.auth) {
        Ok(claims) => claims,
        Err(ProxyError::InvalidToken) | Err(ProxyError::MissingToken) => {
            let (mut send_stream, _recv_stream) = stream.split();
            let resp = http::Response::builder()
                .status(401)
                .body(())
                .unwrap();
            send_stream.send_response(resp).await.ok();
            send_stream.finish().await.ok();
            return Ok(format!("rejected: invalid token for domain {domain}"));
        }
        Err(_) => {
            let (mut send_stream, _recv_stream) = stream.split();
            let resp = http::Response::builder()
                .status(403)
                .body(())
                .unwrap();
            send_stream.send_response(resp).await.ok();
            send_stream.finish().await.ok();
            return Ok(format!("rejected: access denied for domain {domain}"));
        }
    };

    // Evaluate policies
    let konfig_method = match method.as_str() {
        "GET" => HttpMethod::Get,
        "POST" => HttpMethod::Post,
        "PUT" => HttpMethod::Put,
        "DELETE" => HttpMethod::Delete,
        "PATCH" => HttpMethod::Patch,
        "HEAD" => HttpMethod::Head,
        "OPTIONS" => HttpMethod::Options,
        _ => {
            let (mut send_stream, _recv_stream) = stream.split();
            let resp = http::Response::builder()
                .status(405)
                .body(())
                .unwrap();
            send_stream.send_response(resp).await.ok();
            send_stream.finish().await.ok();
            return Ok(format!("rejected: invalid method for domain {domain}"));
        }
    };

    if let Err(ProxyError::AccessDenied) =
        konfig::evaluate_policies(&org, &domain, &konfig_method, &uri_path, &claims)
    {
        let (mut send_stream, _recv_stream) = stream.split();
        let resp = http::Response::builder()
            .status(403)
            .body(())
            .unwrap();
        send_stream.send_response(resp).await.ok();
        send_stream.finish().await.ok();
        return Ok(format!("rejected: policy denied for domain {domain}"));
    }

    // ── 3. Split the h3 stream so send and recv are independent ──────────────
    let (mut send_stream, mut recv_stream) = stream.split();

    // ── 3. Bridge h3 recv → mpsc channel → hyper body ────────────────────────
    //
    // Spawning here is critical: it lets the recv side drain concurrently
    // while the main task is blocked waiting for backend response headers.
    // Without this the QUIC flow-control window fills up and deadlocks.
    let (tx, mut rx) = mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(16);

    tokio::spawn(async move {
        loop {
            match recv_stream.recv_data().await {
                Ok(Some(mut chunk)) => {
                    let bytes = chunk.copy_to_bytes(chunk.remaining());
                    if tx.send(Ok(Frame::data(bytes))).await.is_err() {
                        // Receiver dropped — backend request was cancelled.
                        break;
                    }
                }
                Ok(None) => break, // Client finished sending the request body.
                Err(e) => {
                    let _ = tx
                        .send(Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
                        .await;
                    break;
                }
            }
        }
    });

    let body_stream = async_stream::stream! {
        while let Some(item) = rx.recv().await {
            yield item;
        }
    };
    let outbound_body = StreamBody::new(body_stream).boxed();

    // ── 4. Build the outbound request to the HTTP/1.1 backend ────────────────
    let backend_base = org.upstream.base_url.trim_end_matches('/');
    let uri = format!("{}{}", backend_base, uri_path);
    let mut backend_req = Request::builder().method(method).uri(&uri);

    for (name, value) in req_headers.iter() {
        if !is_forbidden_request_header(name) {
            backend_req = backend_req.header(name, value);
        }
    }

    let backend_req = backend_req.body(outbound_body)?;

    // ── 5. Send to backend ───────────────────────────────────────────────────
    //
    // hyper drives the body stream (via the spawned task above) while
    // waiting for the backend to return response headers — fully concurrent.
    let backend_resp = client
        .request(backend_req)
        .await
        .context("Cannot forward request to backend")?;

    let status = backend_resp.status();
    let resp_headers = backend_resp.headers().clone();

    // ── 6. Forward response headers back to the h3 client ────────────────────
    //
    // Strip hop-by-hop headers — they are illegal in HTTP/3.
    let mut resp_builder = http::Response::builder().status(status);
    for (name, value) in resp_headers.iter() {
        if !is_hop_by_hop(name) {
            resp_builder = resp_builder.header(name, value);
        }
    }

    send_stream
        .send_response(resp_builder.body(())?)
        .await
        .context("Failed to send response headers to h3 client")?;

    // ── 7. Stream the response body back chunk by chunk ───────────────────────
    let mut backend_body = backend_resp.into_body();
    let mut total_bytes: usize = 0;

    while let Some(frame_result) = backend_body.frame().await {
        let frame = frame_result.context("Error reading backend response body")?;
        if let Some(chunk) = frame.data_ref() {
            total_bytes += chunk.len();
            send_stream
                .send_data(chunk.clone())
                .await
                .context("Failed to send response body to h3 client")?;
        }
        // Trailers are intentionally not forwarded here.
        // Add trailer forwarding if your backend uses gRPC or similar.
    }

    // ── 8. Finish the h3 stream ───────────────────────────────────────────────
    //
    // This queues a FIN frame in the QUIC send buffer.
    // The connection driver in the caller (the accept() loop) keeps
    // polling the QUIC state machine after we return, which is what
    // actually delivers the FIN and remaining bytes to the peer.
    // Do NOT drop h3_server_conn in the caller until accept() returns
    // Ok(None) — that is the only correct way to ensure full flush.
    send_stream
        .finish()
        .await
        .context("Failed to finish h3 send stream")?;

    Ok(format!(
        "proxied {uri_path} -> {status} ({total_bytes} bytes streamed)"
    ))
}
