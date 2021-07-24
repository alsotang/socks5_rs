#[tokio::main]
async fn main() {

    let server = socks5_rs::Server::new().await;
    server.serve().await;
}
