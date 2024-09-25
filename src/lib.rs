//! # SOCKS Client Library
//!
//! This library provides a SOCKS client implementation supporting SOCKS4, SOCKS4a, and SOCKS5 protocols.
//! It allows users to connect, bind, and associate UDP through a SOCKS proxy.
use crate::error::SocksError;
use async_trait::async_trait;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;
use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, UdpSocket};

mod bind;
mod connect;
mod error;
mod udp;
mod utils;

const SOCKS_CMD_CONNECT: u8 = 0x01;
const SOCKS_CMD_BIND: u8 = 0x02;
const SOCKS_CMD_UDP_ASSOCIATE: u8 = 0x03;

const SOCKS_ADDR_TYPE_IPV4: u8 = 0x01;
const SOCKS_ADDR_TYPE_IPV6: u8 = 0x04;
const SOCKS_ADDR_TYPE_DOMAIN: u8 = 0x03;

const SOCKS5_AUTH_NONE: u8 = 0x00;
const SOCKS5_AUTH_USERNAME_PASSWORD: u8 = 0x02;

/// Represents the version of the SOCKS protocol.
#[derive(Clone, Copy, Debug)]
enum SocksVersion {
    Socks4,
    Socks4a,
    Socks5,
}

/// A builder for creating SOCKS clients.
#[derive(Debug)]
pub struct SocksClientBuilder {
    proxy_addr: String,
    username: Option<String>,
    password: Option<String>,
    version: Option<SocksVersion>,
}

/// Represents a SOCKS client for different versions of the protocol.
#[derive(Debug)]
struct SocksClientInner {
    proxy_addr: String,
    buf: Vec<u8>,
    stream: Option<TcpStream>,
    bindaddr: Option<SocketAddr>,
    username: Option<String>,
    password: Option<String>,
}

/// Represents a SOCKS client for different versions of the protocol.
#[derive(Debug)]
enum Client {
    Socks4(SocksClientInner),
    Socks4a(SocksClientInner),
    Socks5(SocksClientInner),
}

/// A TCP stream that is connected through a SOCKS proxy.
#[derive(Debug)]
pub struct SocksTcpStream {
    inner: TcpStream,
    bindaddr: SocketAddr,
}

/// A UDP socket that is associated through a SOCKS proxy.
#[derive(Debug)]
pub struct SocksUdpSocket {
    _control: TcpStream,
    inner: UdpSocket,
    bindaddr: SocketAddr,
}

/// A trait for connecting to a target address through a SOCKS proxy.
#[async_trait]
pub trait SocksConnect: Send + Sync {
    /// Connects to the specified target address and port through a SOCKS proxy.
    async fn connect(
        &mut self,
        target_addr: &str,
        target_port: u16,
    ) -> Result<SocksTcpStream, SocksError>;
    /// Connects to the specified target hostname and port through a SOCKS proxy.
    async fn connect_hostname(
        &mut self,
        target_addr: &str,
        target_port: u16,
    ) -> Result<SocksTcpStream, SocksError>;
}

/// A trait for binding to a target address through a SOCKS proxy.
#[async_trait]
pub trait SocksBind: Send + Sync {
    /// Binds to the specified target address and port through a SOCKS proxy.
    /// If the client is not in possession of DST.ADDR and DST.PORT at the time the UDP ASSOCIATE request is create,
    /// it MUST use a port number and address of all zeros.
    async fn bind(&mut self, target_addr: &str, target_port: u16) -> Result<(), SocksError>;
    /// Accepts a connection from the SOCKS proxy.
    async fn accept(&mut self) -> Result<SocksTcpStream, SocksError>;
    /// Gets the bound address from the SOCKS proxy to notify remote sender.
    fn get_proxy_bind_addr(&mut self) -> Option<SocketAddr>;
}

/// A trait for associating a UDP socket through a SOCKS proxy.
#[async_trait]
pub trait SocksUdp: Send + Sync {
    /// Associates a UDP socket to the specified target address and port through a SOCKS proxy.
    async fn udp_associate(
        &mut self,
        target_addr: &str,
        target_port: u16,
    ) -> Result<(), SocksError>;
    /// Gets the UDP socket associated with the SOCKS proxy.
    async fn get_udp_socket(&mut self, bind_addr: &str) -> Result<SocksUdpSocket, SocksError>;
}

impl SocksClientBuilder {
    /// Creates a new `SocksClientBuilder` with the specified proxy IP and port.
    pub fn new(proxyip: &str, proxyport: u16) -> Self {
        Self {
            proxy_addr: format!("{}:{}", proxyip, proxyport),
            username: None,
            password: None,
            version: None,
        }
    }

    /// Sets the username for authentication.
    pub fn username(mut self, username: &str) -> Self {
        self.username = Some(username.to_string());
        self
    }

    /// Sets the password for authentication.
    pub fn password(mut self, password: &str) -> Self {
        self.password = Some(password.to_string());
        self
    }

    /// Sets the SOCKS version to SOCKS4.
    pub fn socks4(mut self) -> Self {
        self.version = Some(SocksVersion::Socks4);
        self
    }

    /// Sets the SOCKS version to SOCKS4a.
    pub fn socks4a(mut self) -> Self {
        self.version = Some(SocksVersion::Socks4a);
        self
    }

    /// Sets the SOCKS version to SOCKS5.
    pub fn socks5(mut self) -> Self {
        self.version = Some(SocksVersion::Socks5);
        self
    }

    /// Builds a TCP client for connecting to a target address.
    pub fn build_tcp_client(self) -> Box<dyn SocksConnect> {
        let inner = SocksClientInner {
            proxy_addr: self.proxy_addr,
            buf: vec![],
            stream: None,
            bindaddr: None,
            username: self.username,
            password: self.password,
        };

        match self.version {
            Some(SocksVersion::Socks4) => Box::new(Client::Socks4(inner)),
            Some(SocksVersion::Socks4a) => Box::new(Client::Socks4a(inner)),
            Some(SocksVersion::Socks5) => Box::new(Client::Socks5(inner)),
            None => Box::new(Client::Socks5(inner)),
        }
    }

    /// Builds a client for binding to a target address.
    pub fn build_listen_client(self) -> Box<dyn SocksBind> {
        let inner = SocksClientInner {
            proxy_addr: self.proxy_addr,
            buf: vec![],
            stream: None,
            bindaddr: None,
            username: self.username,
            password: self.password,
        };

        match self.version {
            Some(SocksVersion::Socks4) => Box::new(Client::Socks4(inner)),
            Some(SocksVersion::Socks4a) => Box::new(Client::Socks4a(inner)),
            Some(SocksVersion::Socks5) => Box::new(Client::Socks5(inner)),
            None => Box::new(Client::Socks5(inner)),
        }
    }

    /// Builds a client for associating a UDP socket.
    pub fn build_udp_client(self) -> Box<dyn SocksUdp> {
        let inner = SocksClientInner {
            proxy_addr: self.proxy_addr,
            buf: vec![],
            stream: None,
            bindaddr: None,
            username: self.username,
            password: self.password,
        };

        match self.version {
            Some(SocksVersion::Socks4) => Box::new(Client::Socks4(inner)),
            Some(SocksVersion::Socks4a) => Box::new(Client::Socks4a(inner)),
            Some(SocksVersion::Socks5) => Box::new(Client::Socks5(inner)),
            None => Box::new(Client::Socks5(inner)),
        }
    }
}

impl SocksTcpStream {
    /// Creates a new `SocksTcpStream` with the specified TCP stream and bound address.
    pub fn new(stream: TcpStream, addr: SocketAddr) -> Self {
        SocksTcpStream {
            inner: stream,
            bindaddr: addr,
        }
    }
    /// Gets the bound address from the SOCKS proxy.
    pub fn get_proxy_bind_addr(&mut self) -> SocketAddr {
        self.bindaddr
    }
}

impl AsyncWrite for SocksTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AsyncRead for SocksTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

#[cfg(test)]
mod test {
    const HTTP_REQUEST: &str = "GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\n\r\n";
    use crate::SocksClientBuilder;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;
    #[tokio::test]
    async fn test_socks4_connect() {
        let mut client = SocksClientBuilder::new("10.206.118.40", 1080)
            .socks4()
            .build_tcp_client();
        let mut stream = client.connect("110.242.68.3", 80).await.unwrap();
        stream.write_all(HTTP_REQUEST.as_bytes()).await.unwrap();
        let mut buf = vec![0; 1024];
        let mut response_buffer = vec![];
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            response_buffer.extend(&buf[..n]);
        }
        assert!(response_buffer.starts_with("HTTP/1.".as_bytes()));
    }

    #[tokio::test]
    async fn test_socks4a_connect() {
        let mut client = SocksClientBuilder::new("10.206.118.122", 1080)
            .socks4a()
            .build_tcp_client();
        let mut stream = client.connect("110.242.68.3", 80).await.unwrap();
        stream.write_all(HTTP_REQUEST.as_bytes()).await.unwrap();
        let mut buf = vec![0; 1024];
        let mut response_buffer = vec![];
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            response_buffer.extend(&buf[..n]);
        }
        assert!(response_buffer.starts_with("HTTP/1.".as_bytes()));
    }

    #[tokio::test]
    async fn test_socks4a_hostname_connect() {
        let mut client = SocksClientBuilder::new("10.206.118.122", 1080)
            .socks4a()
            .build_tcp_client();
        let mut stream = client.connect_hostname("www.baidu.com", 80).await.unwrap();
        stream.write_all(HTTP_REQUEST.as_bytes()).await.unwrap();
        let mut buf = vec![0; 1024];
        let mut response_buffer = vec![];
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            response_buffer.extend(&buf[..n]);
        }
        assert!(response_buffer.starts_with("HTTP/1.".as_bytes()));
    }

    #[tokio::test]
    async fn test_socks5_connect() {
        let mut client = SocksClientBuilder::new("10.206.118.40", 1080)
            .socks5()
            .build_tcp_client();
        let mut stream = client.connect("110.242.68.3", 80).await.unwrap();
        stream.write_all(HTTP_REQUEST.as_bytes()).await.unwrap();
        let mut buf = vec![0; 1024];
        let mut response_buffer = vec![];
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            response_buffer.extend(&buf[..n]);
        }
        assert!(response_buffer.starts_with("HTTP/1.".as_bytes()));
    }

    #[tokio::test]
    async fn test_socks5_connect_hostname() {
        let mut client = SocksClientBuilder::new("10.206.118.40", 1080)
            .socks5()
            .build_tcp_client();
        let mut stream = client.connect_hostname("www.baidu.com", 80).await.unwrap();
        stream.write_all(HTTP_REQUEST.as_bytes()).await.unwrap();
        let mut buf = vec![0; 1024];
        let mut response_buffer = vec![];
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            response_buffer.extend(&buf[..n]);
        }
        assert!(response_buffer.starts_with("HTTP/1.".as_bytes()));
    }

    #[tokio::test]
    async fn test_bind() {
        let mut client = SocksClientBuilder::new("10.206.118.40", 1080)
            .socks5()
            .build_listen_client();
        let target_ip = "0.0.0.0";
        let target_port = 80;
        client.bind(target_ip, target_port).await.unwrap();
        let addr = client.get_proxy_bind_addr().unwrap();
        let mut remote = TcpStream::connect(addr).await.unwrap();
        let _ = remote.write(b"Hello World!").await.unwrap();
        let mut stream = client.accept().await.unwrap();
        remote.flush().await.unwrap();
        let mut buf = vec![0; 1024];
        let _ = stream.read(&mut buf).await.unwrap();
        drop(remote);
        assert!(buf.eq(b"Hello World!"));
    }

    #[tokio::test]
    async fn test_udp() {
        const UDP_DATA: &str = "ABCDEFG";
        let mut client = SocksClientBuilder::new("10.206.118.40", 1080)
            .socks5()
            .build_udp_client();
        client.udp_associate("0.0.0.0", 0).await.unwrap();
        let udp = client.get_udp_socket("0.0.0.0:0").await.unwrap();
        udp.send_udp_data(UDP_DATA.as_bytes(), "10.206.118.122:5553")
            .await
            .unwrap();
        let data = udp.recv_udp_data(5).await.unwrap();
        assert!(data.1.eq(UDP_DATA.as_bytes()));
    }
}
