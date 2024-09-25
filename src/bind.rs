//! # Bind Module
//!
//! This module provides the implementation for binding to a target address through a SOCKS proxy.
use crate::error::*;
use crate::utils::*;
use crate::*;
use async_trait::async_trait;
use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[async_trait]
impl SocksBind for Client {
    /// Binds to the specified target address and port through a SOCKS proxy.
    /// target is address expect the bind reply from.
    /// The socks v4 standard is pretty strict about the meaning,
    /// while the v5 is much more ambiguous.
    /// If it is not required to verify sender to the binding proxy address, use an address with zero.
    ///
    /// # Arguments
    ///
    /// * `target_ip` - The target IP address to bind to.
    /// * `target_port` - The target port to bind to.
    ///
    /// # Returns
    ///
    /// A `Result` containing `()` if the bind operation is successful, or a `SocksError` if an error occurs.
    async fn bind(&mut self, target_ip: &str, target_port: u16) -> Result<(), SocksError> {
        match self {
            Client::Socks4(inner) | Client::Socks4a(inner) => {
                let mut stream = TcpStream::connect(&inner.proxy_addr).await.map_err(|e| SocksError::BindError(e.to_string()))?;
                let username: Cow<[u8]> = match inner.username.as_ref() {
                    Some(username) => Cow::Borrowed(username.as_bytes()),
                    None => Cow::Owned(String::new().into_bytes()),
                };
                let target = target_ip.parse::<Ipv4Addr>().map_err(|e| SocksError::BindError(e.to_string()))?;

                inner.buf.clear();
                let request = &mut inner.buf;
                request.extend_from_slice(&[0x04, SOCKS_CMD_BIND]);
                request.extend_from_slice(&target_port.to_be_bytes());
                request.extend_from_slice(&target.octets());
                request.extend_from_slice(&username);
                request.push(0x00);

                stream.write_all(&request).await.map_err(|e| SocksError::BindError(e.to_string()))?;

                inner.buf.resize(8, 0);
                let mut response = &mut inner.buf;
                stream.read_exact(&mut response).await.map_err(|e| SocksError::BindError(e.to_string()))?;

                //the version of the reply code should be 0 in socks4.protocol
                if response[0] != 0x00 {
                    return Err(SocksError::BindError(format!(
                        "SOCKS4 bind request failed, error {}",
                        "the version of the reply code should be 0"
                    )));
                }

                if response[1] != 0x5A {
                    return Err(SocksError::BindError(format!(
                        "SOCKS4 bind request failed, error {}:{}",
                        response[1],
                        translate_socks4_error(response[1])
                    )));
                }

                //If the DSTIP in the reply is 0 (the value of constant INADDR_ANY),
                //then the client should replace it with the IP address of the SOCKS server to which
                //the cleint is connected.
                if response[4] == 0 && response[5] == 0 && response[6] == 0 && response[7] == 0 {
                    let mut proxy_ip = stream.peer_addr().map_err(|e| SocksError::BindError(e.to_string()))?;
                    let bind_port = u16::from_be_bytes([response[2], response[3]]);
                    proxy_ip.set_port(bind_port);
                    inner.stream = Some(stream);
                    inner.bindaddr = Some(proxy_ip);
                    return Ok(());
                }

                let bind_ip = format!("{}.{}.{}.{}", response[4], response[5], response[6], response[7]);
                let bind_port = u16::from_be_bytes([response[2], response[3]]);
                let bind_addr =
                    format!("{}:{}", bind_ip, bind_port).parse::<SocketAddr>().map_err(|e| SocksError::BindError(e.to_string()))?;

                inner.stream = Some(stream);
                inner.bindaddr = Some(bind_addr);

                return Ok(());
            }

            Client::Socks5(inner) => {
                let mut stream = TcpStream::connect(&inner.proxy_addr).await.map_err(|e| SocksError::BindError(e.to_string()))?;

                let target = target_ip.parse::<IpAddr>().map_err(|e| SocksError::BindError(e.to_string()))?;

                socks5_authenticate(&mut stream, inner).await?;
                inner.buf.clear();
                let request = &mut inner.buf;
                match target {
                    IpAddr::V4(addr) => {
                        request.extend_from_slice(&[0x05, SOCKS_CMD_BIND, 0x00, SOCKS_ADDR_TYPE_IPV4]);
                        request.extend_from_slice(&addr.octets());
                        request.extend_from_slice(&target_port.to_be_bytes());
                        stream.write_all(&request).await.map_err(|e| SocksError::BindError(e.to_string()))?;
                    }
                    IpAddr::V6(addr) => {
                        request.extend_from_slice(&[0x05, SOCKS_CMD_BIND, 0x00, SOCKS_ADDR_TYPE_IPV6]);
                        request.extend_from_slice(&addr.octets());
                        request.extend_from_slice(&target_port.to_be_bytes());
                        stream.write_all(&request).await.map_err(|e| SocksError::BindError(e.to_string()))?;
                    }
                }

                inner.buf.resize(22, 0);

                let bind_response = &mut inner.buf;

                stream.read_exact(&mut bind_response[..4]).await.map_err(|e| SocksError::BindError(e.to_string()))?;

                if bind_response[0] != 0x05 || bind_response[1] != 0x00 {
                    return Err(SocksError::BindError(format!(
                        "SOCKS5 BIND request failed, error {}:{}",
                        bind_response[1],
                        translate_socks5_error(bind_response[1])
                    )));
                }

                let addr_type = bind_response[3];
                let addr_len;
                if addr_type == SOCKS_ADDR_TYPE_IPV4 {
                    addr_len = 4;
                } else if addr_type == SOCKS_ADDR_TYPE_IPV6 {
                    addr_len = 16;
                } else {
                    return Err(SocksError::BindError(format!("Unsupported address type: {:02X}", addr_type)));
                }

                stream.read_exact(&mut bind_response[4..4 + addr_len + 2]).await.map_err(|e| SocksError::BindError(e.to_string()))?;

                let bnd_addr = match addr_type {
                    SOCKS_ADDR_TYPE_IPV4 => {
                        //If the DSTIP in the reply is 0 (the value of constant INADDR_ANY),
                        //then the client should replace it with the IP address of the SOCKS server to which
                        //the cleint is connected.
                        if bind_response[4] == 0 && bind_response[5] == 0 && bind_response[6] == 0 && bind_response[7] == 0 {
                            let mut proxy_ip = stream.peer_addr().map_err(|e| SocksError::BindError(e.to_string()))?;
                            let bind_port = u16::from_be_bytes([bind_response[8], bind_response[9]]);
                            proxy_ip.set_port(bind_port);
                            proxy_ip
                        } else {
                            let mut addr = [0u8; 4];
                            addr.copy_from_slice(&bind_response[4..8]);
                            SocketAddr::from((std::net::Ipv4Addr::from(addr), u16::from_be_bytes([bind_response[8], bind_response[9]])))
                        }
                    }
                    SOCKS_ADDR_TYPE_IPV6 => {
                        //If the DSTIP in the reply is 0 (the value of constant INADDR_ANY),
                        //then the client should replace it with the IP address of the SOCKS server to which
                        //the cleint is connected.
                        if bind_response[4..20].iter().all(|&elem| elem == 0) {
                            let mut proxy_ip = stream.peer_addr().map_err(|e| SocksError::BindError(e.to_string()))?;
                            let bind_port = u16::from_be_bytes([bind_response[20], bind_response[21]]);
                            proxy_ip.set_port(bind_port);
                            proxy_ip
                        } else {
                            let mut addr = [0u8; 16];
                            addr.copy_from_slice(&bind_response[4..20]);
                            SocketAddr::from((std::net::Ipv6Addr::from(addr), u16::from_be_bytes([bind_response[20], bind_response[21]])))
                        }
                    }
                    _ => return Err(SocksError::BindError("Unsupported address type".into())),
                };

                inner.stream = Some(stream);
                inner.bindaddr = Some(bnd_addr);

                return Ok(());
            }
        }
    }

    /// Gets the bound address from the SOCKS proxy.
    ///
    /// # Returns
    ///
    /// An `Option` containing the bound `SocketAddr` if available, or `None` if not.    
    fn get_proxy_bind_addr(&mut self) -> Option<SocketAddr> {
        match self {
            Client::Socks4(inner) | Client::Socks4a(inner) | Client::Socks5(inner) => inner.bindaddr,
        }
    }

    /// Accepts a connection from the SOCKS proxy.
    ///
    /// # Returns
    ///
    /// A `Result` containing a `SocksTcpStream` if the accept operation is successful, or a `SocksError` if an error occurs.    
    async fn accept(&mut self) -> Result<SocksTcpStream, SocksError> {
        match self {
            Client::Socks4(inner) | Client::Socks4a(inner) => {
                let bindaddr: SocketAddr = inner.bindaddr.take().ok_or(SocksError::BindError("accept not ready".into()))?;
                let mut stream = inner.stream.take().ok_or(SocksError::BindError("accept not ready".into()))?;
                let mut second_bind_response_header = [0; 8];
                stream.read_exact(&mut second_bind_response_header).await.map_err(|e| SocksError::BindError(e.to_string()))?;
                //the version of the reply code should be 0 in socks4.protocol
                if second_bind_response_header[0] != 0x00 {
                    return Err(SocksError::BindError(format!(
                        "SOCKS4 bind request failed, error {}",
                        "the version of the reply code should be 0"
                    )));
                }
                if second_bind_response_header[1] != 0x5A {
                    return Err(SocksError::BindError(format!(
                        "SOCKS4 bind request failed, error {}:{}",
                        second_bind_response_header[1],
                        translate_socks4_error(second_bind_response_header[1])
                    )));
                }
                Ok(SocksTcpStream::new(stream, bindaddr))
            }
            Client::Socks5(inner) => {
                let bindaddr: SocketAddr = inner.bindaddr.take().ok_or(SocksError::BindError("accept not ready".into()))?;
                let mut stream = inner.stream.take().ok_or(SocksError::BindError("accept not ready".into()))?;
                let mut second_bind_response_header = [0; 4];
                stream.read_exact(&mut second_bind_response_header).await.map_err(|e| SocksError::BindError(e.to_string()))?;

                if second_bind_response_header[0] != 0x05 || second_bind_response_header[1] != 0x00 {
                    return Err(SocksError::BindError(format!(
                        "SOCKS5 BIND accept failed with code: {:02X}",
                        second_bind_response_header[1]
                    )));
                }

                let addr_type = second_bind_response_header[3];
                let mut bind_response = vec![
                    0;
                    match addr_type {
                        SOCKS_ADDR_TYPE_IPV4 => 10,
                        SOCKS_ADDR_TYPE_IPV6 => 22,
                        _ => return Err(SocksError::BindError("Unsupported address type".into())),
                    }
                ];

                bind_response[..4].copy_from_slice(&second_bind_response_header);
                stream.read_exact(&mut bind_response[4..]).await.map_err(|e| SocksError::BindError(e.to_string()))?;

                Ok(SocksTcpStream::new(stream, bindaddr))
            }
        }
    }
}
