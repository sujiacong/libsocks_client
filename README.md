# SOCKS Client Library

This Rust library provides a SOCKS client implementation supporting SOCKS4, SOCKS4a, and SOCKS5 protocols. It allows users to connect, bind, and associate UDP through a SOCKS proxy.

## Features

+   **SOCKS4, SOCKS4a, and SOCKS5 Support**: The library supports all three versions of the SOCKS protocol, allowing for a wide range of proxy compatibility.
    
+   **TCP Connect and Bind**: Users can establish TCP connections and bind to specific addresses through the proxy.
    
+   **UDP Associate**: The library supports UDP association, enabling UDP traffic to be routed through the SOCKS proxy.
    
+   **Authentication**: Supports username/password authentication for SOCKS5.
    
+   **Asynchronous**: Built using `tokio` for asynchronous I/O operations, making it suitable for high-performance applications.
    

## Installation

Add the following to your `Cargo.toml` file:


```toml
[dependencies]
libsocks_client = "0.1.0"
```

## Usage

### Creating a SOCKS Client

You can create a SOCKS client using the `SocksClientBuilder`. Here’s an example of creating a SOCKS5 client:

```rust
use libsocks_client::SocksClientBuilder;

#[tokio::main]
async fn main() {
    let mut client = SocksClientBuilder::new("127.0.0.1", 1080)
        .socks5()
        .username("user")
        .password("pass")
        .build_tcp_client();

    let mut stream = client.connect("220.181.38.150", 80).await.unwrap();
    // Use the stream to send and receive data
}
```

### Connecting to a Target Address

To connect to a target address through the SOCKS proxy use local dns lookup:

```rust
let mut stream = client.connect("www.example.com", 80).await.unwrap();
```

To connect to a target domain through the SOCKS proxy use remote dns lookup:

```rust
let mut stream = client.connect_hostname("www.example.com", 80).await.unwrap();
```

### Binding to a Target Address

To bind to a target address through the SOCKS proxy:

```rust
client.bind("0.0.0.0", 80).await.unwrap();
let addr = client.get_proxy_bind_addr().unwrap();
//notify server to connect to this addr
//...
//accept server connection
let mut stream = client.accept().await.unwrap();
```

### Associating a UDP Socket

To associate a UDP socket through the SOCKS proxy:

```rust
client.udp_associate("0.0.0.0", 0).await.unwrap();
let udp = client.get_udp_socket("0.0.0.0:0").await.unwrap();
udp.send_udp_data(b"Hello", "example.com:80").await.unwrap();
let (addr, data) = udp.recv_udp_data(5).await.unwrap();
```

## Examples

The library includes several examples in the `tests` module of the `lib.rs` file. You can run these tests to see the library in action:

```sh
cargo test
```

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue if you encounter any problems or have suggestions for improvements.

## License

This project is licensed under the MIT License. See the [LICENSE](https://github.com/sujiacong/libsocks_client/blob/main/LICENSE) file for more details.

