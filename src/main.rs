mod websocket;

use base64::encode;
use bytes::{buf, Buf, BytesMut};
use crypto::digest::Digest;
use crypto::sha1::Sha1;
use hyper::{
    service::{make_service_fn, service_fn},
    upgrade::Upgraded,
    Body, Request, Response, Server, StatusCode,
};
use nom::AsBytes;
use pretty_hex::PrettyHex;
use std::{convert::Infallible, future::Future, net::SocketAddr};
use tokio::io::AsyncReadExt;
use tokio::task;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

async fn handle_upgraded(mut conn: Upgraded) -> Result<()> {
    let mut buffer = BytesMut::with_capacity(4096);
    let _len = conn.read_buf(&mut buffer).await?;
    let (rest, frame) = websocket::Frame::parse(buffer.as_bytes()).expect("a");
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
    let websocket_key = req
        .headers()
        .get("Sec-WebSocket-Key")
        .expect("Sec-WebSocket-Key header not found.");
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

#[tokio::main]
async fn main() {
    let addr = SocketAddr::from(([127, 0, 0, 1], 3456));
    let make_svc = make_service_fn(|_conn| async move { Ok::<_, Infallible>(service_fn(upgrade)) });

    let server = Server::bind(&addr).serve(make_svc);

    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}
