use std::fmt;

///rfc1928
pub(crate) fn translate_socks5_error(err_code: u8) -> &'static str {
    match err_code {
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "Network unreachable",
        0x04 => "Host unreachable",
        0x05 => "Connection refused",
        0x06 => "TTL expired",
        0x07 => "Command not supported",
        0x08 => "Address type not supported",
        _ => "socks5 Unknown error",
    }
}

pub(crate) fn translate_socks4_error(err_code: u8) -> &'static str {
    match err_code {
        0x5b => "request rejected or failed",
        0x5c => "request rejected becasue SOCKS server cannot connect to identd on the client",
        0x5d => "request rejected because the client program and identd report different user-ids",
        _ => "socks4 Unknown error",
    }
}

#[derive(Debug)]
pub enum SocksError {
    AuthenticationError(String),
    ConnectionError(String),
    BindError(String),
    UdpAssociateError(String),
}

impl fmt::Display for SocksError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SocksError::AuthenticationError(msg) => write!(f, "Authentication error: {}", msg),
            SocksError::ConnectionError(msg) => write!(f, "Connection error: {}", msg),
            SocksError::BindError(msg) => write!(f, "Bind error: {}", msg),
            SocksError::UdpAssociateError(msg) => write!(f, "UDP associate error: {}", msg),
        }
    }
}

impl std::error::Error for SocksError {}
