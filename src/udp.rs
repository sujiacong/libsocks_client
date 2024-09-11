#[allow(non_snake_case)]
use async_trait::async_trait;
use tokio::net::{TcpStream,UdpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout,Duration};
use std::net::{SocketAddr,ToSocketAddrs};
use crate::*;
use crate::error::*;
use crate::utils::*;

#[async_trait]
impl SocksUdp for Client {
    /// Associates a UDP socket to the specified target address and port through a SOCKS proxy.
    /// If the client is not in possession of DST.ADDR and DST.PORT at the time the UDP ASSOCIATE request is create, 
    /// it MUST use a port number and address of all zeros.
    /// # Arguments
    ///
    /// * `target_addr` - The target address to associate with.
    /// * `target_port` - The target port to associate with.
    ///
    /// # Returns
    ///
    /// A `Result` containing `()` if the association is successful, or a `SocksError` if an error occurs.
    async fn udp_associate(&mut self, target_addr: &str, target_port: u16) -> Result<(), SocksError>
    {
        match self {
            Client::Socks4(_inner) | Client::Socks4a(_inner) => {
                return Err(SocksError::UdpAssociateError("socks4/socks4a not support udp".into()));
            }
            Client::Socks5(inner) => {
                let mut stream = TcpStream::connect(&inner.proxy_addr).await
                .map_err(|e| SocksError::UdpAssociateError(e.to_string()))?;

                let target = format!("{}:{}",target_addr,target_port);
                let (target_host,target_port)  = parse_target_address(&target)
                .map_err(|e| SocksError::UdpAssociateError(e.to_string()))?;

                socks5_authenticate(&mut stream, &inner).await?;

                let mut udp_associate_request = vec![0x05, SOCKS_CMD_UDP_ASSOCIATE, 0x00];
                match target_host {
                    TargetHost::Ipv4(ip) => {
                        udp_associate_request.push(0x01);
                        udp_associate_request.extend_from_slice(&ip.octets());
                    }
                    TargetHost::Domain(domain) => {
                        udp_associate_request.push(0x03);
                        udp_associate_request.push(domain.len() as u8);
                        udp_associate_request.extend_from_slice(domain.as_bytes());
                    }
                    TargetHost::Ipv6(ip) => {
                        udp_associate_request.push(0x04);
                        udp_associate_request.extend_from_slice(&ip.octets());
                    }
                }
                
                udp_associate_request.extend_from_slice(&target_port.to_be_bytes());
                stream.write_all(&udp_associate_request).await
                .map_err(|e| SocksError::UdpAssociateError(e.to_string()))?;

                let mut udp_associate_response_header = [0; 4];
                stream.read_exact(&mut udp_associate_response_header).await
                .map_err(|e| SocksError::UdpAssociateError(e.to_string()))?;

                if udp_associate_response_header[0] != 0x05 || udp_associate_response_header[1] != 0x00 {
                    return Err(SocksError::UdpAssociateError(format!("SOCKS5 UDP ASSOCIATE request failed, error {}",translate_socks5_error(udp_associate_response_header[1]))));
                }

                let addr_type = udp_associate_response_header[3];
                let mut udp_associate_response = vec![0; match addr_type {
                    SOCKS_ADDR_TYPE_IPV4 => 10,
                    SOCKS_ADDR_TYPE_IPV6 => 22,
                    _ => return Err(SocksError::UdpAssociateError("Unsupported address type".into())),
                }];
                udp_associate_response[..4].copy_from_slice(&udp_associate_response_header);
                stream.read_exact(&mut udp_associate_response[4..]).await
                .map_err(|e| SocksError::UdpAssociateError(e.to_string()))?;

                let udp_proxy_addr = match addr_type {
                    SOCKS_ADDR_TYPE_IPV4 => {
                        let mut addr = [0u8; 4];
                        addr.copy_from_slice(&udp_associate_response[4..8]);
                        SocketAddr::from((std::net::Ipv4Addr::from(addr), u16::from_be_bytes([udp_associate_response[8], udp_associate_response[9]])))
                    }
                    SOCKS_ADDR_TYPE_IPV6 => {
                        let mut addr = [0u8; 16];
                        addr.copy_from_slice(&udp_associate_response[4..20]);
                        SocketAddr::from((std::net::Ipv6Addr::from(addr), u16::from_be_bytes([udp_associate_response[20], udp_associate_response[21]])))
                    }
                    _ => return Err(SocksError::UdpAssociateError("Unsupported address type".into())),
                };
                inner.stream = Some(stream);
                inner.bindaddr = Some(udp_proxy_addr);
                Ok(())
            }
        }
    }
    /// Gets the UDP socket associated with the SOCKS proxy.
    ///
    /// # Arguments
    ///
    /// * `bind_addr` - The address to bind the UDP socket to.
    ///
    /// # Returns
    ///
    /// A `Result` containing a `SocksUdpSocket` if the operation is successful, or a `SocksError` if an error occurs.
    async fn get_udp_socket(&mut self, bind_addr: &str) -> Result<SocksUdpSocket,SocksError>
    {
        let addr = bind_addr.to_socket_addrs()
        .map_err(|e| SocksError::UdpAssociateError(e.to_string()))?.next()
        .ok_or(SocksError::UdpAssociateError(format!("Invalid address {:?}",bind_addr)))?;

        let sock = UdpSocket::bind(addr).await
        .map_err(|e| SocksError::UdpAssociateError(e.to_string()))?;

        match self {
            Client::Socks4(_inner) => {
                return Err(SocksError::UdpAssociateError("socks4/socks4a not support udp".into()));
            }
            Client::Socks4a(_inner) => {
                return Err(SocksError::UdpAssociateError("socks4/socks4a not support udp".into()));
            }
            Client::Socks5(inner) => {
                let proxy_addr = inner.bindaddr.take().ok_or(SocksError::UdpAssociateError("udp_associate not ready".into()))?;
                let tcpcontrol = inner.stream.take().ok_or(SocksError::UdpAssociateError("udp_associate not ready".into()))?;
                sock.connect(proxy_addr).await
                .map_err(|e| SocksError::UdpAssociateError(e.to_string()))?;
                Ok(SocksUdpSocket::new(sock,tcpcontrol,proxy_addr))
            }
        }
    }
}

impl SocksUdpSocket {
    /// Creates a new `SocksUdpSocket` with the specified UDP socket, control stream, and bound address.
    ///
    /// # Arguments
    ///
    /// * `socket` - The UDP socket.
    /// * `stream` - The control TCP stream.
    /// * `addr` - The bound address.
    ///
    /// # Returns
    ///
    /// A new `SocksUdpSocket`.    
    pub fn new(socket: UdpSocket,stream:TcpStream, addr: SocketAddr) -> Self {
        SocksUdpSocket { inner: socket, bindaddr: addr,_control: stream}
    }

    /// Gets the UDP address from the SOCKS proxy.
    ///
    /// # Returns
    ///
    /// The bound `SocketAddr`.
    pub fn get_proxy_udp_addr(&mut self) -> SocketAddr
    {
        self.bindaddr
    }

    /// Sends UDP data to the specified target address.
    ///
    /// # Arguments
    ///
    /// * `buf` - The data to send.
    /// * `target_addr` - The target address to send the data to.
    ///
    /// # Returns
    ///
    /// A `Result` containing the number of bytes sent if successful, or a `SocksError` if an error occurs.    
    pub async fn send_udp_data(&self, buf: &[u8], target_addr:&str) -> Result<usize, SocksError> {
        let packet = build_udp_packet(buf, target_addr)
        .map_err(|e| SocksError::UdpAssociateError(e.to_string()))?;
        let ret = self.inner.send_to(&packet, self.bindaddr).await
        .map_err(|e| SocksError::UdpAssociateError(e.to_string()))?;
        Ok(ret)
    }

    /// Receives UDP data with a timeout.
    ///
    /// # Arguments
    ///
    /// * `tm` - The timeout duration in seconds.
    ///
    /// # Returns
    ///
    /// A `Result` containing the received data and the sender's address if successful, or a `SocksError` if an error occurs.
    pub async fn recv_udp_data(&self, tm: u64) -> Result<(SocketAddr, Vec<u8>), SocksError>
    {
        let mut buf = vec![0;2048];
        match timeout(Duration::from_secs(tm), self.inner.recv(&mut buf[..])).await{
            Ok(result) => {
                match result {
                    Ok(len) => {
                        let packet = unpack_udp_packet(&buf, len)
                        .map_err(|e| SocksError::UdpAssociateError(e.to_string()))?;
                        Ok(packet)
                    },
                    Err(err) => Err(SocksError::UdpAssociateError(format!("recv_udp_data failed {:?}",err))),
                }
            },
            Err(_err) => Err(SocksError::UdpAssociateError("recv_udp_data timeout".into())),
        }
    }
}