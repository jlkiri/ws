mod websocket;

use base64::encode;
use bytes::BytesMut;
use color_eyre::Report;
use crypto::{digest::Digest, sha1::Sha1};
use hyper::{
    header::ToStrError,
    service::{make_service_fn, service_fn},
    upgrade::Upgraded,
    Body, Request, Response, Server, StatusCode,
};
use nom::AsBytes;
use std::{convert::Infallible, future::Future, net::SocketAddr, num::ParseIntError};
use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::task;
use tracing::{error, info, warn};
use tracing_subscriber::{self, EnvFilter};
use websocket::Frame;

type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Unknown error.")]
    Any,
    #[error("Internal error.")]
    Internal,
    #[error("I/O error: {0}.")]
    IoError(#[from] std::io::Error),
    #[error("Parser error: {0}.")]
    ParseError(String),
    #[error("Upgrade error: {0}")]
    UpgradeError(#[from] InvalidUpgrade),
    #[error("hyper error: {0}.")]
    HyperError(#[from] hyper::Error),
    #[error("hyper::http error: {0}.")]
    HyperHttpError(#[from] hyper::http::Error),
}

#[derive(Error, Debug)]
pub enum InvalidUpgrade {
    #[error("Invalid Sec-WebSocket-Version value.")]
    InvalidVersionString(#[from] ParseIntError),
    #[error("Invalid Sec-WebSocket-Version.")]
    InvalidVersion,
    #[error("Required header not found: {0}.")]
    HeaderNotFound(String),
}

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

fn decode(target: &mut [u8], source: &[u8], mask: [u8; 4], len: usize) {
    for i in 0..len {
        target[i] = source[i] ^ mask[i % 4];
    }
}

async fn handle_upgraded(mut conn: Upgraded) -> Result<()> {
    let mut buffer = BytesMut::with_capacity(4096);
    let len = conn.read_buf(&mut buffer).await?;
    let frame_bytes = (&buffer[..len]).to_owned();
    let (rest, frame) = Frame::from_bytes(frame_bytes)?;

    let mut message = vec![0; frame.length as usize];
    let mask = frame.masking_key.to_be_bytes();

    decode(&mut message, &rest, mask, frame.length as usize);

    println!("message: {}", String::from_utf8_lossy(&message));

    Ok(())
}

fn spawn_and_log_error<F>(fut: F) -> task::JoinHandle<()>
where
    F: Future<Output = Result<()>> + Send + 'static,
{
    task::spawn(async move {
        if let Err(e) = fut.await {
            warn!("Websocket connection error: {}", e);
        }
    })
}

async fn upgrade(req: Request<Body>) -> std::result::Result<Response<Body>, Error> {
    info!("Incoming upgrade request.");

    let handler_fut =
        async {
            let websocket_key = req
                .headers()
                .get("Sec-WebSocket-Key")
                .ok_or(InvalidUpgrade::HeaderNotFound("Sec-WebSocket-Key".into()))?;

            let websocket_version = req.headers().get("Sec-WebSocket-Version").ok_or(
                InvalidUpgrade::HeaderNotFound("Sec-WebSocket-Version".into()),
            )?;

            let ver = websocket_version
                .to_str()
                .map_err(|_| Error::Internal)
                .map(|res| {
                    res.parse::<i32>()
                        .map_err(|e| InvalidUpgrade::InvalidVersionString(e))
                })??;

            if ver != 13 {
                return Err(InvalidUpgrade::InvalidVersion.into());
            }

            let accept_key = generate_accept_key(websocket_key.as_bytes());

            let response = Response::builder()
                .status(StatusCode::SWITCHING_PROTOCOLS)
                .header("Sec-WebSocket-Accept", accept_key)
                .header("Upgrade", "websocket")
                .header("Connection", "Upgrade")
                .body(Body::empty())?;

            spawn_and_log_error(async {
                let upgraded_conn = hyper::upgrade::on(req).await?;
                handle_upgraded(upgraded_conn).await?;
                Ok(())
            });

            Ok::<_, Error>(response)
        };

    handler_fut.await.or_else(|e| {
        warn!("Error during connection upgrade: {}", e);
        let response = Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::empty())?;
        Ok(response)
    })
}

fn concat<T: Clone>(a: &[T], b: &[T]) -> Vec<T> {
    a.iter().cloned().chain(b.iter().cloned()).collect()
}

fn generate_accept_key(websocket_key: &[u8]) -> String {
    let mut hasher = Sha1::new();
    let combined = concat(websocket_key, WS_GUID.as_bytes());
    hasher.input(&combined);
    let mut output_buf = vec![0; hasher.output_bytes()];
    hasher.result(&mut output_buf);
    let accept_key = encode(output_buf);
    accept_key
}

fn setup() -> std::result::Result<(), Report> {
    if std::env::var("RUST_LIB_BACKTRACE").is_err() {
        std::env::set_var("RUST_LIB_BACKTRACE", "full")
    }

    color_eyre::install()?;

    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info")
    }

    tracing_subscriber::fmt::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    Ok(())
}

#[tokio::main]
async fn main() -> std::result::Result<(), Report> {
    setup()?;

    let addr = SocketAddr::from(([127, 0, 0, 1], 3456));
    let make_svc = make_service_fn(|_conn| async move { Ok::<_, Infallible>(service_fn(upgrade)) });

    let server = Server::bind(&addr).serve(make_svc);

    info!("Listening on 127.0.0.1:3456...");

    if let Err(e) = server.await {
        warn!("Server error: {}", e);
    }

    Ok(())
}
