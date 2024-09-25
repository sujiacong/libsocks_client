//! # Connect Module
//!
//! This module provides the implementation for connecting to a target address through a SOCKS proxy.
use crate::error::*;
use crate::utils::*;
use crate::*;
use async_trait::async_trait;
use std::borrow::Cow;
use std::net::{SocketAddr, ToSocketAddrs};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[async_trait]
impl SocksConnect for Client {
    /// Connects to the specified target address and port through a SOCKS proxy.
    ///
    /// # Arguments
    ///
    /// * `target_addr` - The target address to connect to.
    /// * `target_port` - The target port to connect to.
    ///
    /// # Returns
    ///
    /// A `Result` containing a `SocksTcpStream` if the connection is successful, or a `SocksError` if an error occurs.
    async fn connect(&mut self, target_addr: &str, target_port: u16) -> Result<SocksTcpStream, SocksError> {
        match self {
            Client::Socks4(inner) => {
                let target_str = format!("{}:{}", target_addr, target_port);
                let target = target_str
                    .to_socket_addrs()
                    .map_err(|e| SocksError::ConnectionError(e.to_string()))?
                    .next()
                    .ok_or(SocksError::ConnectionError(format!("Invalid address {} {}", target_addr, target_port)))?;
                let ipv4 = match target {
                    SocketAddr::V4(addr) => addr,
                    SocketAddr::V6(_) => {
                        return Err(SocksError::ConnectionError("socks4 not support ipv6".into()));
                    }
                };
                let mut stream = TcpStream::connect(&inner.proxy_addr).await.map_err(|e| SocksError::ConnectionError(e.to_string()))?;
                let username: Cow<[u8]> = match inner.username.as_ref() {
                    Some(username) => Cow::Borrowed(username.as_bytes()),
                    None => Cow::Owned(String::new().into_bytes()),
                };
                inner.buf.clear();
                let request = &mut inner.buf;
                request.extend_from_slice(&[0x04, SOCKS_CMD_CONNECT]);
                request.extend_from_slice(&target.port().to_be_bytes());
                request.extend_from_slice(&ipv4.ip().octets());
                request.extend_from_slice(&username);
                request.push(0x00);
                stream.write_all(&request).await.map_err(|e| SocksError::ConnectionError(e.to_string()))?;

                inner.buf.resize(8, 0);
                let mut response = &mut inner.buf;
                stream.read_exact(&mut response).await.map_err(|e| SocksError::ConnectionError(e.to_string()))?;

                if response[0] == 0x00 && response[1] == 0x5A {
                    let bind_ip = format!("{}.{}.{}.{}", response[4], response[5], response[6], response[7]);
                    let bind_port = u16::from_be_bytes([response[2], response[3]]);
                    let bind_addr = format!("{}:{}", bind_ip, bind_port)
                        .parse::<SocketAddr>()
                        .map_err(|e| SocksError::ConnectionError(e.to_string()))?;

                    Ok(SocksTcpStream::new(stream, bind_addr))
                } else {
                    return Err(SocksError::ConnectionError(format!(
                        "SOCKS4 Connect request failed, error {}",
                        translate_socks4_error(response[1])
                    )));
                }
            }
            Client::Socks4a(inner) => {
                let target_str = format!("{}:{}", target_addr, target_port);
                let target = target_str
                    .to_socket_addrs()
                    .map_err(|e| SocksError::ConnectionError(e.to_string()))?
                    .next()
                    .ok_or(SocksError::ConnectionError(format!("Invalid address {} {}", target_addr, target_port)))?;
                let ipv4 = match target {
                    SocketAddr::V4(addr) => addr,
                    SocketAddr::V6(_) => {
                        return Err(SocksError::ConnectionError("socks4a not support ipv6".into()));
                    }
                };

                let username: Cow<[u8]> = match inner.username.as_ref() {
                    Some(username) => Cow::Borrowed(username.as_bytes()),
                    None => Cow::Owned(String::new().into_bytes()),
                };

                let mut stream = TcpStream::connect(&inner.proxy_addr).await.map_err(|e| SocksError::ConnectionError(e.to_string()))?;

                inner.buf.clear();
                let request = &mut inner.buf;

                request.extend_from_slice(&[0x04, SOCKS_CMD_CONNECT]);
                request.extend_from_slice(&target_port.to_be_bytes());
                request.extend_from_slice(&[0, 0, 0, 1]);
                request.extend_from_slice(&username);
                request.push(0x00);
                request.extend_from_slice(ipv4.ip().to_string().as_bytes());
                request.push(0x00);

                stream.write_all(&request).await.map_err(|e| SocksError::ConnectionError(e.to_string()))?;

                inner.buf.resize(8, 0);
                let mut response = &mut inner.buf;

                stream.read_exact(&mut response).await.map_err(|e| SocksError::ConnectionError(e.to_string()))?;

                if response[0] == 0x00 && response[1] == 0x5A {
                    let bind_ip = format!("{}.{}.{}.{}", response[4], response[5], response[6], response[7]);
                    let bind_port = u16::from_be_bytes([response[2], response[3]]);
                    let bind_addr = format!("{}:{}", bind_ip, bind_port)
                        .parse::<SocketAddr>()
                        .map_err(|e| SocksError::ConnectionError(e.to_string()))?;

                    Ok(SocksTcpStream::new(stream, bind_addr))
                } else {
                    return Err(SocksError::ConnectionError(format!(
                        "SOCKS4A Connect request failed, error {}",
                        translate_socks4_error(response[1])
                    )));
                }
            }
            Client::Socks5(inner) => {
                let target_str = format!("{}:{}", target_addr, target_port);
                let target = target_str
                    .to_socket_addrs()
                    .map_err(|e| SocksError::ConnectionError(e.to_string()))?
                    .next()
                    .ok_or(SocksError::ConnectionError(format!("Invalid address {} {}", target_addr, target_port)))?;

                let mut stream = TcpStream::connect(&inner.proxy_addr).await.map_err(|e| SocksError::ConnectionError(e.to_string()))?;

                socks5_authenticate(&mut stream, inner).await?;

                inner.buf.clear();
                let request = &mut inner.buf;

                match target {
                    SocketAddr::V4(addr4) => {
                        request.extend_from_slice(&[0x05, SOCKS_CMD_CONNECT, 0x00, SOCKS_ADDR_TYPE_IPV4]);
                        request.extend_from_slice(&addr4.ip().octets());
                        request.extend_from_slice(&target.port().to_be_bytes());

                        stream.write_all(&request).await.map_err(|e| SocksError::ConnectionError(e.to_string()))?;
                    }
                    SocketAddr::V6(addr6) => {
                        request.extend_from_slice(&[0x05, SOCKS_CMD_CONNECT, 0x00, SOCKS_ADDR_TYPE_IPV6]);
                        request.extend_from_slice(&addr6.ip().octets());
                        request.extend_from_slice(&target.port().to_be_bytes());

                        stream.write_all(&request).await.map_err(|e| SocksError::ConnectionError(e.to_string()))?;
                    }
                };

                inner.buf.resize(22, 0);
                let response = &mut inner.buf;

                stream.read_exact(&mut response[..4]).await.map_err(|e| SocksError::ConnectionError(e.to_string()))?;

                let addr_type = response[3];
                let addr_len;
                if addr_type == SOCKS_ADDR_TYPE_IPV4 {
                    addr_len = 4;
                } else if addr_type == SOCKS_ADDR_TYPE_IPV6 {
                    addr_len = 16;
                } else {
                    return Err(SocksError::ConnectionError(format!("Unsupported address type: {:02X}", addr_type)));
                }

                stream.read_exact(&mut response[4..4 + addr_len + 2]).await.map_err(|e| SocksError::ConnectionError(e.to_string()))?;

                if response[1] != 0x00 {
                    return Err(SocksError::ConnectionError(format!(
                        "SOCKS5 Connect request failed, error {}",
                        translate_socks5_error(response[1])
                    )));
                }

                let bindaddr;
                if addr_type == SOCKS_ADDR_TYPE_IPV4 {
                    let mut addr = [0u8; 4];
                    addr.copy_from_slice(&response[4..8]);
                    bindaddr = SocketAddr::from((std::net::Ipv4Addr::from(addr), u16::from_be_bytes([response[8], response[9]])))
                } else if addr_type == SOCKS_ADDR_TYPE_IPV6 {
                    let mut addr = [0u8; 16];
                    addr.copy_from_slice(&response[4..20]);
                    bindaddr = SocketAddr::from((std::net::Ipv6Addr::from(addr), u16::from_be_bytes([response[20], response[21]])))
                } else {
                    return Err(SocksError::ConnectionError(format!("Unsupported address type: {:02X}", addr_type)));
                }

                Ok(SocksTcpStream::new(stream, bindaddr))
            }
        }
    }
    /// Connects to the specified target hostname and port through a SOCKS proxy.
    ///
    /// # Arguments
    ///
    /// * `target_addr` - The target hostname to connect to.
    /// * `target_port` - The target port to connect to.
    ///
    /// # Returns
    ///
    /// A `Result` containing a `SocksTcpStream` if the connection is successful, or a `SocksError` if an error occurs.
    async fn connect_hostname(&mut self, target_addr: &str, target_port: u16) -> Result<SocksTcpStream, SocksError> {
        match self {
            Client::Socks4(_) => Err(SocksError::ConnectionError("SOCKS4 does not support remote domain".to_string())),
            Client::Socks4a(inner) => {
                let (target_host, target_port) = parse_target_address(&format!("{}:{}", target_addr, target_port))
                    .map_err(|e| SocksError::ConnectionError(e.to_string()))?;

                let targetaddr = match target_host {
                    TargetHost::Ipv4(ip) => ip.to_string(),
                    TargetHost::Domain(domain) => domain,
                    TargetHost::Ipv6(_ip) => return Err(SocksError::ConnectionError("SOCKS4a not support ipv6 ddress".into())),
                };

                let mut stream = TcpStream::connect(&inner.proxy_addr).await.map_err(|e| SocksError::ConnectionError(e.to_string()))?;

                let username: Cow<[u8]> = match inner.username.as_ref() {
                    Some(username) => Cow::Borrowed(username.as_bytes()),
                    None => Cow::Owned(String::new().into_bytes()),
                };

                inner.buf.clear();
                let request = &mut inner.buf;

                request.extend_from_slice(&[0x04, SOCKS_CMD_CONNECT]);
                request.extend_from_slice(&target_port.to_be_bytes());
                request.extend_from_slice(&[0, 0, 0, 1]);
                request.extend_from_slice(&username);
                request.push(0x00);
                request.extend_from_slice(&targetaddr.as_bytes());
                request.push(0x00);

                stream.write_all(&request).await.map_err(|e| SocksError::ConnectionError(e.to_string()))?;

                inner.buf.resize(8, 0);
                let mut response = &mut inner.buf;
                stream.read_exact(&mut response).await.map_err(|e| SocksError::ConnectionError(e.to_string()))?;

                if response[0] == 0x00 && response[1] == 0x5a {
                    let bind_ip = format!("{}.{}.{}.{}", response[4], response[5], response[6], response[7]);
                    let bind_port = u16::from_be_bytes([response[2], response[3]]);
                    let bind_addr = format!("{}:{}", bind_ip, bind_port)
                        .parse::<SocketAddr>()
                        .map_err(|e| SocksError::ConnectionError(e.to_string()))?;

                    Ok(SocksTcpStream::new(stream, bind_addr))
                } else {
                    return Err(SocksError::ConnectionError(format!(
                        "SOCKS4A Connect request failed, error {}",
                        translate_socks4_error(response[1])
                    )));
                }
            }
            Client::Socks5(inner) => {
                let mut stream = TcpStream::connect(&inner.proxy_addr).await.map_err(|e| SocksError::ConnectionError(e.to_string()))?;

                socks5_authenticate(&mut stream, inner).await?;

                inner.buf.clear();
                let request = &mut inner.buf;

                request.extend_from_slice(&[0x05, SOCKS_CMD_CONNECT, 0x00, SOCKS_ADDR_TYPE_DOMAIN]);
                request.push(target_addr.len() as u8);
                request.extend_from_slice(&target_addr.as_bytes());
                request.extend_from_slice(&target_port.to_be_bytes());

                stream.write_all(&request).await.map_err(|e| SocksError::ConnectionError(e.to_string()))?;

                inner.buf.resize(22, 0);
                let response = &mut inner.buf;
                stream.read_exact(&mut response[..4]).await.map_err(|e| SocksError::ConnectionError(e.to_string()))?;

                let addr_type = response[3];
                let addr_len;
                if addr_type == SOCKS_ADDR_TYPE_IPV4 {
                    addr_len = 4;
                } else if addr_type == SOCKS_ADDR_TYPE_IPV6 {
                    addr_len = 16;
                } else {
                    return Err(SocksError::ConnectionError(format!("Unsupported address type: {:02X}", addr_type)));
                }

                stream.read_exact(&mut response[4..4 + addr_len + 2]).await.map_err(|e| SocksError::ConnectionError(e.to_string()))?;

                if response[0] != 0x05 || response[1] != 0x00 {
                    return Err(SocksError::ConnectionError(format!(
                        "SOCKS5 CONNECT request failed, error {}:{}",
                        response[1],
                        translate_socks5_error(response[1])
                    )));
                }

                let bindaddr;
                if addr_type == SOCKS_ADDR_TYPE_IPV4 {
                    let mut addr = [0u8; 4];
                    addr.copy_from_slice(&response[4..8]);
                    bindaddr = SocketAddr::from((std::net::Ipv4Addr::from(addr), u16::from_be_bytes([response[8], response[9]])))
                } else if addr_type == SOCKS_ADDR_TYPE_IPV6 {
                    let mut addr = [0u8; 16];
                    addr.copy_from_slice(&response[4..20]);
                    bindaddr = SocketAddr::from((std::net::Ipv6Addr::from(addr), u16::from_be_bytes([response[20], response[21]])))
                } else {
                    return Err(SocksError::ConnectionError(format!("Unsupported address type: {:02X}", addr_type)));
                }

                Ok(SocksTcpStream::new(stream, bindaddr))
            }
        }
    }
}
