mod websocket;
use color_eyre::Report;

use base64::encode;
use bytes::{buf, BytesMut};
use crypto::{digest::Digest, sha1::Sha1};
use hyper::{
    service::{make_service_fn, service_fn},
    upgrade::Upgraded,
    Body, Request, Response, Server, StatusCode,
};
use nom::AsBytes;
use std::{convert::Infallible, fmt::Display, future::Future, net::SocketAddr, sync::Arc};
use tokio::io::AsyncReadExt;
use tokio::task;

type Result<T> = std::result::Result<T, Report>;

#[derive(Debug)]
pub enum Error {
    Derp,
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Error lol.")
    }
}

impl std::error::Error for Error {}

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

async fn handle_upgraded(mut conn: Upgraded) -> Result<()> {
    let mut buffer = BytesMut::with_capacity(4096);
    let frame_bytes = buffer.as_bytes().to_owned();
    let _len = conn.read_buf(&mut buffer).await?;
    let (rest, frame) = websocket::Frame::from_bytes(frame_bytes)?;
    let mut msg = vec![0; frame.length as usize];
    let byte_mask = frame.masking_key.to_be_bytes();

    for i in 0..frame.length as usize {
        msg[i] = rest[i] ^ byte_mask[i % 4];
    }

    println!("message: {}", String::from_utf8_lossy(&msg));

    Ok(())
}

fn spawn_and_log_error<F>(fut: F) -> task::JoinHandle<()>
where
    F: Future<Output = Result<()>> + Send + 'static,
{
    task::spawn(async move {
        if let Err(e) = fut.await {
            eprintln!("{}", e)
        }
    })
}

async fn upgrade(req: Request<Body>) -> Result<Response<Body>> {
    let websocket_key = req.headers().get("Sec-WebSocket-Key").ok_or(Error::Derp)?;
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

    Ok(response)
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

fn setup() -> Result<()> {
    if std::env::var("RUST_LIB_BACKTRACE").is_err() {
        std::env::set_var("RUST_LIB_BACKTRACE", "1")
    }
    color_eyre::install()?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    setup()?;

    let addr = SocketAddr::from(([127, 0, 0, 1], 3456));
    let make_svc = make_service_fn(|_conn| async move { Ok::<_, Infallible>(service_fn(upgrade)) });

    let server = Server::bind(&addr).serve(make_svc);

    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }

    Ok(())
}
