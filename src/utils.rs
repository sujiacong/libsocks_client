//! # Utils Module
//!
//! This module provides utility functions for parsing target addresses and building/unpacking UDP packets.
use tokio::io;
use std::str::FromStr;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::*;

/// Represents the target host type.
pub(crate) enum TargetHost {
    Ipv4(std::net::Ipv4Addr),
    Domain(String),
    Ipv6(std::net::Ipv6Addr),
}

/// Parses the target address and port.
///
/// # Arguments
///
/// * `addr` - The target address in the format "host:port".
///
/// # Returns
///
/// A `Result` containing the parsed `TargetHost` and port if successful, or an `io::Error` if an error occurs.
pub(crate) fn parse_target_address(addr: &str) -> io::Result<(TargetHost, u16)> {
    let mut parts = addr.split(':');
    let host = parts.next().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid address"))?;
    let port = parts.next().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid address"))?;
    let port = u16::from_str(port).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid port"))?;

    if let Ok(ip) = std::net::Ipv4Addr::from_str(host) {
        Ok((TargetHost::Ipv4(ip), port))
    } else if let Ok(ip) = std::net::Ipv6Addr::from_str(host) {
        Ok((TargetHost::Ipv6(ip), port))
    } else {
        Ok((TargetHost::Domain(host.to_string()), port))
    }
}

/// Builds a UDP packet for sending data.
///
/// # Arguments
///
/// * `data` - The data to send.
/// * `target_addr` - The target address in the format "host:port".
///
/// # Returns
///
/// A `Result` containing the built UDP packet if successful, or an `io::Error` if an error occurs.
pub(crate) fn build_udp_packet(data: &[u8], target_addr:&str) -> io::Result<Vec<u8>> {

    let (target_addr, target_port) = parse_target_address(target_addr)?;

    let mut packet = match target_addr {
        TargetHost::Ipv4(_) => vec![0; 10 + data.len()],
        TargetHost::Ipv6(_) => vec![0; 22 + data.len()],
        TargetHost::Domain(ref domain) => vec![0; 7 + domain.len() + data.len()],
    };

    packet[0] = 0; // RSV
    packet[1] = 0; // RSV
    packet[2] = 0; // FRAG

    match target_addr {
        TargetHost::Ipv4(addr) => {
            packet[3] = 0x01; // ATYP: IPv4
            packet[4..8].copy_from_slice(&addr.octets());
            packet[8..10].copy_from_slice(&target_port.to_be_bytes());
            packet[10..].copy_from_slice(data);
        }
        TargetHost::Ipv6(addr) => {
            packet[3] = 0x04; // ATYP: IPv6
            packet[4..20].copy_from_slice(&addr.octets());
            packet[20..22].copy_from_slice(&target_port.to_be_bytes());
            packet[22..].copy_from_slice(data);
        }
        TargetHost::Domain(ref domain) => {
            let domain_len = domain.len();
            packet[3] = 0x03; // ATYP: Domain
            packet[4] = domain_len as u8;
            packet[5..5 + domain_len].copy_from_slice(domain.as_bytes());
            packet[5 + domain_len..7 + domain_len].copy_from_slice(&target_port.to_be_bytes());
            packet[7 + domain_len..].copy_from_slice(data);
        }
    }

    Ok(packet)
}

/// Unpacks a UDP packet received from the SOCKS proxy.
///
/// # Arguments
///
/// * `data` - The received UDP packet.
/// * `n` - The number of bytes received.
///
/// # Returns
///
/// A `Result` containing the unpacked data and the sender's address if successful, or an `io::Error` if an error occurs.
pub (crate) fn unpack_udp_packet(data: &[u8], n: usize) -> io::Result<(SocketAddr, Vec<u8>)>
{
    if n < 4
    {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "packet size too small",
        ));
    }
    let atyp = data[3];
    match atyp {
        0x01 => {
            if n < 10
            {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "packet size too small",
                ));
            }
            let ip = [data[4], data[5], data[6], data[7]];
            let port = u16::from_be_bytes([data[8], data[9]]);
            let dst_addr = SocketAddr::from((ip, port));
            let data = data[10..n].to_vec();
            Ok((dst_addr, data))
        }
        0x04 => {
            if n < 22
            {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "packet size too small",
                ));
            }
            let ip = [
                data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11],
                data[12], data[13], data[14], data[15], data[16], data[17], data[18], data[19],
            ];
            let port = u16::from_be_bytes([data[20], data[21]]);
            let dst_addr = SocketAddr::from((ip, port));
            let data = data[22..n].to_vec();
            Ok((dst_addr, data))
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Unsupported address type",
            ));
        }
    }
}

/// Performs SOCKS5 authentication with the proxy server.
///
/// This function sends the authentication methods supported by the client to the proxy server
/// and handles the negotiation of the authentication method. If the server selects a supported
/// authentication method, the function proceeds to authenticate using the provided username and password.
///
/// # Arguments
///
/// * `stream` - A mutable reference to the `TcpStream` connected to the SOCKS5 proxy server.
/// * `inner` - A reference to the `SocksClientInner` containing the client's configuration, including username and password.
///
/// # Returns
///
/// A `Result` containing `()` if the authentication is successful, or a `SocksError` if an error occurs.
///
/// # Errors
///
/// This function will return an error in the following cases:
/// - If the connection to the proxy server fails.
/// - If the proxy server selects an unsupported authentication method.
/// - If the authentication with the proxy server fails.
/// - If the username or password is missing when required.
pub (crate) async fn socks5_authenticate(stream: &mut TcpStream, inner: &SocksClientInner) -> Result<(), SocksError> {
    let auth_methods = vec![0x05, 0x02, SOCKS5_AUTH_NONE, SOCKS5_AUTH_USERNAME_PASSWORD];
    stream.write_all(&auth_methods).await.map_err(|e| SocksError::ConnectionError(e.to_string()))?;

    let mut auth_negotiation = [0; 2];
    stream.read_exact(&mut auth_negotiation).await.map_err(|e| SocksError::ConnectionError(e.to_string()))?;

    let mut auth_response = [0; 2];

    if auth_negotiation[1] == SOCKS5_AUTH_USERNAME_PASSWORD {
        let username = inner.username.as_ref().ok_or(SocksError::AuthenticationError("missing username".into()))?;
        let password = inner.password.as_ref().ok_or(SocksError::AuthenticationError("missing password".into()))?;

        let mut auth_request = vec![0x01];
        auth_request.push(username.len() as u8);
        auth_request.extend_from_slice(&username.as_bytes());
        auth_request.push(password.len() as u8);
        auth_request.extend_from_slice(&password.as_bytes());

        stream.write_all(&auth_request).await.map_err(|e| SocksError::ConnectionError(e.to_string()))?;
        stream.read_exact(&mut auth_response).await.map_err(|e| SocksError::ConnectionError(e.to_string()))?;

        if auth_response[1] != 0x00 {
            return Err(SocksError::AuthenticationError(format!("SOCKS5 authentication failed with method: {:02X}", auth_response[1])));
        }
    } else if auth_negotiation[1] != 0x00 {
        return Err(SocksError::AuthenticationError(format!("SOCKS5 authentication failed with method: {:02X}", auth_response[1])));
    }

    Ok(())
}