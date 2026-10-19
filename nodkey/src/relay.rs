//! Signed calls to the Nodkey relay (docs/agent-protocol.md, "Relay API").

use std::time::Duration;

use nodkey_proto::{
    AgentInfo, ErrorBody, KeyPair, PairingClaimed, PairingCode, RequestEnvelope, SealedBox, auth,
};
use reqwest::{Method, StatusCode, Url};

/// The relay unless `--relay`, `NODKEY_RELAY` or `relay` in `config.json` says otherwise.
pub const DEFAULT_RELAY: &str = "https://relay.nodkey.app";

/// Whether to note on stderr what the relay did with the push (on for `nodkey mcp`, whose stderr
/// is a log; off for the command line unless `NODKEY_DEBUG` is set).
pub static LOG_PUSH: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// Errors from relay calls.
#[derive(Debug)]
pub enum RelayError {
    /// The relay answered with an error status.
    Status {
        status: u16,
        code: String,
        message: String,
    },
    /// The relay could not be reached or the connection broke.
    Transport(String),
    /// The relay answered with something that is not the protocol.
    Protocol(String),
}

impl RelayError {
    /// True for errors worth retrying during a long poll.
    pub fn is_transient(&self) -> bool {
        match self {
            RelayError::Transport(_) => true,
            RelayError::Status { status, .. } => *status >= 500,
            RelayError::Protocol(_) => false,
        }
    }
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelayError::Status {
                status,
                code,
                message,
            } => {
                write!(f, "relay answered {status} {code}")?;
                if !message.is_empty() {
                    write!(f, ": {message}")?;
                }
                Ok(())
            }
            RelayError::Transport(m) => write!(f, "relay unreachable: {m}"),
            RelayError::Protocol(m) => write!(f, "unexpected relay response: {m}"),
        }
    }
}

impl std::error::Error for RelayError {}

/// Result of one long-poll round.
pub enum Poll<T> {
    /// The value arrived.
    Ready(T),
    /// The relay's wait ran out (`204`); ask again.
    Pending,
    /// The pairing or request is gone (`404` / `410`).
    Gone,
}

/// Who signs a call.
pub struct Signer<'a> {
    pub id: &'a str,
    pub keys: &'a KeyPair,
}

/// A relay client. Cheap to clone (the HTTP client shares its connection pool).
#[derive(Clone)]
pub struct Relay {
    base: Url,
    http: reqwest::Client,
}

impl Relay {
    /// A client for the relay at `base` (`https://host[/prefix]`). Plain `http` is only for a
    /// relay on this computer (`localhost`, `127.0.0.1`, `[::1]`), such as the fake relay in tests.
    /// The client follows no redirects.
    pub fn new(base: &str) -> Result<Self, RelayError> {
        let trimmed = base.trim().trim_end_matches('/');
        let base = Url::parse(trimmed)
            .map_err(|e| RelayError::Protocol(format!("relay URL {trimmed:?}: {e}")))?;
        let local = matches!(base.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
        match base.scheme() {
            "https" => {}
            "http" if local => {}
            _ => {
                return Err(RelayError::Protocol(format!(
                    "relay URL {trimmed:?} must be https (http only for localhost, 127.0.0.1 or [::1])"
                )));
            }
        }
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("nodkey/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| RelayError::Transport(e.to_string()))?;
        Ok(Relay { base, http })
    }

    /// The base URL.
    pub fn base(&self) -> &str {
        self.base.as_str().trim_end_matches('/')
    }

    fn url(&self, path: &str) -> Result<Url, RelayError> {
        let mut s = String::with_capacity(self.base.as_str().len() + path.len());
        s.push_str(self.base());
        s.push_str(path);
        Url::parse(&s).map_err(|e| RelayError::Protocol(format!("URL: {e}")))
    }

    /// One signed call. `timeout` bounds the whole exchange (long polls pass wait + margin).
    async fn call(
        &self,
        signer: &Signer<'_>,
        method: Method,
        path: &str,
        body: Option<(&'static str, Vec<u8>)>,
        timeout: Duration,
    ) -> Result<(StatusCode, Vec<u8>), RelayError> {
        let url = self.url(path)?;
        let signed_path = match url.query() {
            Some(q) => format!("{}?{q}", url.path()),
            None => url.path().to_owned(),
        };
        let body_bytes: &[u8] = body.as_ref().map_or(&[], |(_, b)| b.as_slice());
        let header = auth::sign(
            &signer.keys.signing_key(),
            signer.id,
            method.as_str(),
            &signed_path,
            nodkey_proto::unix_now(),
            body_bytes,
        );
        let mut req = self
            .http
            .request(method, url)
            .timeout(timeout)
            .header(auth::HEADER, header);
        if let Some((content_type, bytes)) = body {
            req = req
                .header(reqwest::header::CONTENT_TYPE, content_type)
                .body(bytes);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| RelayError::Transport(describe(&e)))?;
        let status = resp.status();
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| RelayError::Transport(describe(&e)))?;
        Ok((status, bytes.to_vec()))
    }

    /// `POST /v1/pairings`, signed with the key in its own body.
    pub async fn start_pairing(
        &self,
        signer: &Signer<'_>,
        info: &AgentInfo,
    ) -> Result<PairingCode, RelayError> {
        let body = json_body(info);
        let (status, bytes) = self
            .call(
                signer,
                Method::POST,
                "/v1/pairings",
                Some(body),
                Duration::from_secs(30),
            )
            .await?;
        expect_json(status, &bytes, &[StatusCode::CREATED])
    }

    /// `GET /v1/pairings/{code}?wait=N`.
    pub async fn wait_pairing(
        &self,
        signer: &Signer<'_>,
        code: &str,
        wait: u64,
    ) -> Result<Poll<PairingClaimed>, RelayError> {
        let path = format!("/v1/pairings/{code}?wait={wait}");
        let (status, bytes) = self
            .call(signer, Method::GET, &path, None, poll_timeout(wait))
            .await?;
        poll_result(status, &bytes)
    }

    /// `POST /v1/phones/{phone_id}/requests`.
    pub async fn post_request(
        &self,
        signer: &Signer<'_>,
        phone_id: &str,
        envelope: &RequestEnvelope,
    ) -> Result<(), RelayError> {
        let path = format!("/v1/phones/{phone_id}/requests");
        let (status, bytes) = self
            .call(
                signer,
                Method::POST,
                &path,
                Some(json_body(envelope)),
                Duration::from_secs(30),
            )
            .await?;
        expect_status(status, &bytes, StatusCode::ACCEPTED)?;
        // The relay says what happened to the push; for diagnostics on stderr only.
        if LOG_PUSH.load(std::sync::atomic::Ordering::Relaxed)
            && let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes)
            && let Some(push) = v.get("push").and_then(|p| p.as_str())
        {
            eprintln!("nodkey: push {push}");
        }
        Ok(())
    }

    /// `PUT /v1/requests/{request_id}/attachment` with the raw body `enc ‖ ct`.
    pub async fn put_attachment(
        &self,
        signer: &Signer<'_>,
        request_id: &str,
        body: Vec<u8>,
    ) -> Result<(), RelayError> {
        let path = format!("/v1/requests/{request_id}/attachment");
        let (status, bytes) = self
            .call(
                signer,
                Method::PUT,
                &path,
                Some(("application/octet-stream", body)),
                Duration::from_secs(60),
            )
            .await?;
        expect_status(status, &bytes, StatusCode::NO_CONTENT)
    }

    /// `DELETE /v1/agents/{agent_id}/phones/{phone_id}`: the agent leaves. Returns `false` when
    /// the relay did not know the pairing (`404`), which counts as done.
    pub async fn leave(&self, signer: &Signer<'_>, phone_id: &str) -> Result<bool, RelayError> {
        let path = format!("/v1/agents/{}/phones/{phone_id}", signer.id);
        let (status, bytes) = self
            .call(signer, Method::DELETE, &path, None, Duration::from_secs(30))
            .await?;
        match status {
            StatusCode::NOT_FOUND => Ok(false),
            _ => expect_status(status, &bytes, StatusCode::NO_CONTENT).map(|()| true),
        }
    }

    /// `GET /v1/requests/{request_id}?wait=N`.
    pub async fn wait_answer(
        &self,
        signer: &Signer<'_>,
        request_id: &str,
        wait: u64,
    ) -> Result<Poll<SealedBox>, RelayError> {
        let path = format!("/v1/requests/{request_id}?wait={wait}");
        let (status, bytes) = self
            .call(signer, Method::GET, &path, None, poll_timeout(wait))
            .await?;
        poll_result(status, &bytes)
    }
}

fn poll_timeout(wait: u64) -> Duration {
    Duration::from_secs(wait + 15)
}

fn json_body<T: serde::Serialize>(v: &T) -> (&'static str, Vec<u8>) {
    (
        "application/json",
        serde_json::to_vec(v).expect("serializable"),
    )
}

fn describe(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        "timed out".into()
    } else if e.is_connect() {
        "could not connect".into()
    } else {
        e.to_string()
    }
}

fn status_error(status: StatusCode, bytes: &[u8]) -> RelayError {
    let (code, message) = match serde_json::from_slice::<ErrorBody>(bytes) {
        Ok(e) => (e.error, e.message),
        Err(_) => (
            status.canonical_reason().unwrap_or("error").to_owned(),
            String::new(),
        ),
    };
    RelayError::Status {
        status: status.as_u16(),
        code,
        message,
    }
}

fn expect_json<T: serde::de::DeserializeOwned>(
    status: StatusCode,
    bytes: &[u8],
    ok: &[StatusCode],
) -> Result<T, RelayError> {
    if !ok.contains(&status) {
        return Err(status_error(status, bytes));
    }
    serde_json::from_slice(bytes).map_err(|e| RelayError::Protocol(e.to_string()))
}

fn expect_status(status: StatusCode, bytes: &[u8], expected: StatusCode) -> Result<(), RelayError> {
    if status == expected {
        Ok(())
    } else if status.is_success() {
        Err(RelayError::Protocol(format!(
            "expected status {}, got {}",
            expected.as_u16(),
            status.as_u16()
        )))
    } else {
        Err(status_error(status, bytes))
    }
}

fn poll_result<T: serde::de::DeserializeOwned>(
    status: StatusCode,
    bytes: &[u8],
) -> Result<Poll<T>, RelayError> {
    match status {
        StatusCode::OK => serde_json::from_slice(bytes)
            .map(Poll::Ready)
            .map_err(|e| RelayError::Protocol(e.to_string())),
        StatusCode::NO_CONTENT => Ok(Poll::Pending),
        StatusCode::NOT_FOUND | StatusCode::GONE => Ok(Poll::Gone),
        _ => Err(status_error(status, bytes)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_url_rules() {
        assert_eq!(
            Relay::new("https://r.example/").unwrap().base(),
            "https://r.example"
        );
        assert_eq!(
            Relay::new("https://r.example/pre/").unwrap().base(),
            "https://r.example/pre"
        );
        assert!(Relay::new("ftp://r.example").is_err());
        assert!(Relay::new("not a url").is_err());
    }

    #[test]
    fn plain_http_only_on_this_computer() {
        for ok in [
            "http://localhost:8787",
            "http://127.0.0.1:9",
            "http://[::1]:8787/pre",
            "http://LOCALHOST",
        ] {
            assert!(Relay::new(ok).is_ok(), "{ok}");
        }
        for bad in [
            "http://r.example",
            "http://192.168.1.10:8787",
            "http://127.0.0.2",
            "http://localhost.r.example",
            "http://[::2]",
        ] {
            let e = Relay::new(bad).err().expect(bad).to_string();
            assert!(e.contains("must be https"), "{bad}: {e}");
        }
    }

    #[tokio::test]
    async fn redirects_are_not_followed() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf).await.unwrap();
            s.write_all(
                b"HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:9/elsewhere\r\n\
                  Content-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        });
        let relay = Relay::new(&format!("http://{addr}")).unwrap();
        let keys = KeyPair::generate();
        let signer = Signer {
            id: "AAAAAAAAAAAAAAAAAAAAAA",
            keys: &keys,
        };
        let (status, _) = relay
            .call(&signer, Method::GET, "/v1/x", None, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(status, StatusCode::TEMPORARY_REDIRECT);
        server.await.unwrap();
    }

    #[test]
    fn error_bodies() {
        let e = status_error(
            StatusCode::FORBIDDEN,
            br#"{"error":"not_paired","message":"unknown agent"}"#,
        );
        assert_eq!(
            e.to_string(),
            "relay answered 403 not_paired: unknown agent"
        );
        let e = status_error(StatusCode::BAD_GATEWAY, b"<html>");
        assert!(e.is_transient());
        assert_eq!(e.to_string(), "relay answered 502 Bad Gateway");
    }
}
