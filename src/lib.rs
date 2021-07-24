use std::{io, net::ToSocketAddrs, usize};

use bytes::Buf;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const SOCKS_VERSION: u8 = 0x05;
const RESERVED: u8 = 0x00;

enum AuthMethod {
    /// No Authentication
    NoAuth = 0x00,
    // GssApi = 0x01,
    /// Authenticate with a username / password
    UserPass = 0x02,
}

enum Rep {
    Success = 0x00,
}

impl From<Rep> for u8 {
    fn from(rep: Rep) -> u8 {
        rep as u8
    }
}

impl From<AuthMethod> for u8 {
    fn from(auth_method: AuthMethod) -> u8 {
        auth_method as u8
    }
}

#[derive(thiserror::Error, Debug)]
enum Socks5Error {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Address type not supported")]
    AddressTypeNotSupported,
    // #[error("unknown error")]
    // Unknown,
}

pub struct Server {
    listener: TcpListener,
}

impl Server {
    pub async fn new() -> Self {
        Server {
            listener: TcpListener::bind("127.0.0.1:1080").await.unwrap(),
        }
    }
    pub async fn serve(&self) {
        while let Ok((stream, _)) = self.listener.accept().await {
            tokio::spawn(async move {
                Socks5Handler::init(stream).await;
            });
        }
    }
}

struct Socks5Handler {
    stream: TcpStream,
    socks_version: u8,
    auth_nmethods: u8,
}

impl Socks5Handler {
    async fn init(stream: TcpStream) {
        let mut handler = Socks5Handler {
            stream,
            socks_version: 0,
            auth_nmethods: 0,
        };

        let mut header = [0u8; 2];

        handler.stream.read_exact(&mut header).await.unwrap();

        handler.socks_version = header[0];
        handler.auth_nmethods = header[1];

        if handler.handle_req().await.is_err() {
            handler.stream.shutdown().await.unwrap();
        };
    }

    async fn handle_req(&mut self) -> Result<(), io::Error> {
        self.auth().await?;

        let req = Socks5Req::from_stream(&mut self.stream).await.unwrap();

        let socket_addr = req.as_socket_addr().unwrap();
        let mut target = TcpStream::connect(&socket_addr[..]).await?;

        self.stream
            .write_all(&[
                SOCKS_VERSION,
                Rep::Success.into(),
                RESERVED,
                0x01,
                0,
                0,
                0,
                0,
                0,
                0,
            ])
            .await?;

        tokio::io::copy_bidirectional(&mut self.stream, &mut target).await?;

        Ok(())
    }

    async fn auth(&mut self) -> Result<(), io::Error> {
        let mut methods = vec!(0u8; self.auth_nmethods as usize);
        self.stream.read_exact(&mut methods).await?;

        let mut response = [0u8; 2];
        response[0] = SOCKS_VERSION;
        response[1] = AuthMethod::NoAuth.into();
        self.stream.write_all(&response).await?;

        Ok(())
    }
}

enum Atyp {
    V4 = 0x01,
    Domain = 0x03,
    V6 = 0x04,
}

impl Atyp {
    fn from_u8(n: u8) -> Result<Self, Socks5Error> {
        match n {
            0x01 => Ok(Atyp::V4),
            0x03 => Ok(Atyp::Domain),
            0x04 => Ok(Atyp::V6),
            _ => Err(Socks5Error::AddressTypeNotSupported),
        }
    }
}

enum Command {
    // Connect = 0x01,
}
impl From<Command> for u8 {
    fn from(command: Command) -> u8 {
        command as u8
    }
}

struct Socks5Req {
    // version: u8,
    // command: u8,
    atyp: Atyp,
    addr: Vec<u8>,
    port: u16,
}
impl Socks5Req {
    async fn from_stream(stream: &mut TcpStream) -> Result<Self, Socks5Error> {
        let mut first4 = [0u8; 4];
        stream.read_exact(&mut first4).await?;

        let atyp = Atyp::from_u8(first4[3]).unwrap();

        let addr = match atyp {
            Atyp::V4 => {
                let mut addr = [0u8; 4];
                stream.read_exact(&mut addr).await?;
                addr.to_vec()
            }
            Atyp::Domain => {
                let mut addr_len_buf = [0u8; 1];
                stream.read_exact(&mut addr_len_buf).await?;
                let mut addr = vec![0u8; addr_len_buf[0] as usize];
                stream.read_exact(&mut addr).await?;
                addr.to_vec()
            }
            Atyp::V6 => {
                let mut addr = [0u8; 16];
                stream.read_exact(&mut addr).await?;
                addr.to_vec()
            }
        };

        let mut port = [0u8; 2];
        stream.read_exact(&mut port).await?;
        let port = (&port[..]).get_u16();

        Ok(Socks5Req {
            // version: SOCKS_VERSION,
            // command: Command::Connect.into(),
            atyp,
            addr,
            port,
        })
    }

    fn as_socket_addr(&self) -> Result<Vec<SocketAddr>, Socks5Error> {
        let addr = &self.addr;
        let port = self.port;

        match self.atyp {
            Atyp::V4 => Ok(vec![SocketAddr::from(SocketAddrV4::new(
                Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]),
                port,
            ))]),
            Atyp::Domain => {
                let mut domain = String::from_utf8(addr.clone()).unwrap();
                domain.push(':');
                domain.push_str(&port.to_string());

                Ok(domain.to_socket_addrs()?.collect())
            }
            Atyp::V6 => {
                let mut addr = &addr[..];
                Ok(vec![SocketAddr::from(SocketAddrV6::new(
                    Ipv6Addr::new(
                        addr.get_u16(),
                        addr.get_u16(),
                        addr.get_u16(),
                        addr.get_u16(),
                        addr.get_u16(),
                        addr.get_u16(),
                        addr.get_u16(),
                        addr.get_u16(),
                    ),
                    port,
                    0,
                    0,
                ))])
            }
        }
    }
}
