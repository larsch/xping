mod ping;

use std::{env, net};

fn main() {
    let target = env::args().nth(1).unwrap();
    let target = dns_lookup::lookup_host(&target).unwrap();
    let target = target.first().unwrap();
    let target_sa = match target {
        net::IpAddr::V4(v4addr) => net::SocketAddr::V4(net::SocketAddrV4::new(*v4addr, 58)),
        net::IpAddr::V6(v6addr) => net::SocketAddr::V6(net::SocketAddrV6::new(*v6addr, 58, 0, 0)),
    };

    let ping_protocol = ping::PingProtocol::new(target_sa).unwrap();

    ping_protocol.send().unwrap();

    let response = ping_protocol.recv().unwrap();
    println!("response from {:?}", response);

    // Rest of the code...
}
