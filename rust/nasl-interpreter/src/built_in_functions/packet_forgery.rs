// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

//! Defines NASL packet forgery functions

use std::net::Ipv4Addr;

use crate::{Context, ContextType, FunctionErrorKind, NaslFunction, NaslValue, Register};
use pnet::packet::{self, ip::IpNextHeaderProtocol, ipv4::checksum};

use super::{hostname::get_host_ip, misc::random_impl};

/// print the raw packet
pub fn display_packet(vector: &[u8]) {
    let mut s: String = "".to_string();
    let mut count = 0;

    for e in vector {
        s.push_str(&format!("{:02x}", &e));
        count += 1;
        if count % 2 == 0 {
            s.push(' ');
        }
        if count % 16 == 0 {
            s.push('\n');
        }
    }
    println!("{}", s);
}

/// Forge an IP datagram inside the block of data. It takes following arguments:
///  
/// - data: is the payload.
/// - ip_hl: is the IP header length in 32 bits words. 5 by default.
/// - ip_id: is the datagram ID; by default, it is random.
/// - ip_len: is the length of the datagram. By default, it is 20 plus the length of the data field.
/// - ip_off: is the fragment offset in 64 bits words. By default, 0.
/// - ip_p: is the IP protocol. 0 by default.
/// - ip_src: is the source address in ASCII. NASL will convert it into an integer in network order.
/// - ip_dst: is the destination address in ASCII. NASL will convert it into an integer in network order. By default it takes the target IP address via call to **[plug_get_host_ip(3)](plug_get_host_ip.md)**. This option looks dangerous, but since anybody can edit an IP packet with the string functions, we make it possible to set directly during the forge.
/// - ip_sum: is the packet header checksum. It will be computed by default.
/// - ip_tos: is the “type of service” field. 0 by default
/// - ip_ttl: is the “Time To Live”. 64 by default.
/// - ip_v is: the IP version. 4 by default.
///
/// Returns the IP datagram or NULL on error.
fn forge_ip_packet<K>(
    register: &Register,
    configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    let dst_addr = get_host_ip(configs)?;

    if dst_addr.is_ipv6() {
        return Err(FunctionErrorKind::Diagnostic(
            "forge_ip_packet: No valid dst_addr could be determined via call to get_host_ip()"
                .to_string(),
            Some(NaslValue::Null),
        ));
    }

    let data = match register.named("data") {
        Some(ContextType::Value(NaslValue::Data(d))) => d.clone(),
        Some(ContextType::Value(NaslValue::String(d))) => d.as_bytes().to_vec(),
        Some(ContextType::Value(NaslValue::Number(d))) => d.to_be_bytes().to_vec(),
        _ => Vec::<u8>::new(),
    };

    let total_length = 20 + data.len();
    let mut buf = vec![0; total_length];
    let mut pkt = packet::ipv4::MutableIpv4Packet::new(&mut buf).unwrap();
    pkt.set_total_length(total_length as u16);

    if !data.is_empty() {
        pkt.set_payload(&data);
    }

    let ip_hl = match register.named("ip_hl") {
        Some(ContextType::Value(NaslValue::Number(x))) => *x as u8,
        _ => 5_u8,
    };
    pkt.set_header_length(ip_hl);

    let ip_v = match register.named("ip_v") {
        Some(ContextType::Value(NaslValue::Number(x))) => *x as u8,
        _ => 4_u8,
    };
    pkt.set_version(ip_v);

    let ip_tos = match register.named("ip_tos") {
        Some(ContextType::Value(NaslValue::Number(x))) => *x as u8,
        _ => 0_u8,
    };
    pkt.set_dscp(ip_tos);

    let ip_ttl = match register.named("ip_ttl") {
        Some(ContextType::Value(NaslValue::Number(x))) => *x as u8,
        _ => 0_u8,
    };
    pkt.set_ttl(ip_ttl);

    let ip_id = match register.named("ip_id") {
        Some(ContextType::Value(NaslValue::Number(x))) => *x as u16,
        _ => random_impl()? as u16,
    };
    pkt.set_identification(ip_id.to_be());

    let ip_off = match register.named("ip_off") {
        Some(ContextType::Value(NaslValue::Number(x))) => *x as u16,
        _ => 0_u16,
    };
    pkt.set_fragment_offset(ip_off);

    let ip_p = match register.named("ip_p") {
        Some(ContextType::Value(NaslValue::Number(x))) => *x as u8,
        _ => 0_u8,
    };
    pkt.set_next_level_protocol(IpNextHeaderProtocol::new(ip_p));

    match register.named("ip_src") {
        Some(ContextType::Value(NaslValue::String(x))) => {
            match x.parse::<Ipv4Addr>() {
                Ok(ip) => {
                    pkt.set_source(ip);
                }
                Err(e) => {
                    return Err(FunctionErrorKind::Diagnostic(
                        format!("forge_ip_packet invalid ip_src: {}", e),
                        Some(NaslValue::Null),
                    ));
                }
            };
            x.to_string()
        }
        _ => String::new(),
    };

    match register.named("ip_dst") {
        Some(ContextType::Value(NaslValue::String(x))) => {
            match x.parse::<Ipv4Addr>() {
                Ok(ip) => {
                    pkt.set_destination(ip);
                }
                Err(e) => {
                    return Err(FunctionErrorKind::Diagnostic(
                        format!("forge_ip_packet invalid ip_dst: {}", e),
                        Some(NaslValue::Null),
                    ));
                }
            };
            x.to_string()
        }
        _ => {
            match dst_addr.to_string().parse::<Ipv4Addr>() {
                Ok(ip) => {
                    pkt.set_destination(ip);
                }
                Err(e) => {
                    return Err(FunctionErrorKind::Diagnostic(
                        format!("forge_ip_packet invalid ip: {}", e),
                        Some(NaslValue::Null),
                    ));
                }
            };
            dst_addr.to_string()
        }
    };

    let ip_sum = match register.named("ip_sum") {
        Some(ContextType::Value(NaslValue::Number(x))) => (*x as u16).to_be(),
        _ => checksum(&pkt.to_immutable()),
    };
    pkt.set_checksum(ip_sum);

    Ok(NaslValue::Data(buf))
}

/// Set element from a IP datagram. Its arguments are:
///  
/// - ip: IP datagram to set fields on
/// - ip_hl: IP header length in 32 bits words, 5 by default
/// - ip_id: datagram ID, random by default
/// - ip_len: length of the datagram, 20 plus the length of the data
/// - ip_off: fragment offset in 64 bits words, 0 by default
/// - ip_p: IP protocol, 0 by default
/// - ip_src: source address in ASCII, NASL will convert it into an integer in network order
/// - ip_sum: packet header checksum, it will be computed by default
/// - ip_tos: type of service field, 0 by default
/// - ip_ttl: time to live field, 64 by default
/// - ip_v: IP version, 4 by default
///  
/// Returns the modified IP datagram
fn set_ip_elements<K>(
    _register: &Register,
    _configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    Ok(NaslValue::Null)
}

/// Get an IP element from a IP datagram. It returns a data block or an integer, according to the type of the element. Its arguments are:
/// - ip: is the IP datagram.
/// - element: is the name of the field to get
///   
/// Valid IP elements to get are:
/// - ip_v
/// - ip_id
/// - ip_hl
/// - ip_tos
/// - ip_len
/// - ip_off
/// - ip_ttl
/// - ip_p
/// - ip_sum
/// - ip_src
/// - ip_dst
fn get_ip_element<K>(
    _register: &Register,
    _configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    Ok(NaslValue::Null)
}

/// Receive a list of IP packets and print them in a readable format in the screen.
fn dump_ip_packet<K>(
    register: &Register,
    _configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    let positional = register.positional();
    if positional.is_empty() {
        return Ok(NaslValue::Null);
    }

    for ip in positional.iter() {
        match ip {
            NaslValue::Data(data) => {
                let pkt = packet::ipv4::Ipv4Packet::new(data).unwrap();
                println!("------\n");
                println!("\tip_hl  : {:?}", pkt.get_header_length());
                println!("\tip_v   : {:?}", pkt.get_version());
                println!("\tip_tos : {:?}", pkt.get_dscp());
                println!("\tip_len : {:?}", pkt.get_total_length());
                println!("\tip_id  : {:?}", pkt.get_identification());
                println!("\tip_off : {:?}", pkt.get_fragment_offset());
                println!("\tip_ttl : {:?}", pkt.get_ttl());
                // TODO: match pkt.get_next_level_protocol()
                println!("\tip_sum  : {:?}", pkt.get_checksum());
                println!("\tip_src : {:?}", pkt.get_source().to_string());
                println!("\tip_dst : {:?}", pkt.get_destination().to_string());
            }
            _ => {
                return Err(FunctionErrorKind::WrongArgument(
                    "valid ip packet".to_string(),
                ));
            }
        }
    }

    Ok(NaslValue::Null)
}

/// Add a option to a specified IP datagram.
///  
/// - ip: is the IP datagram
/// - code: is the identifier of the option to add
/// - length: is the length of the option data
/// - value: is the option data
fn insert_ip_options<K>(
    _register: &Register,
    _configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    Ok(NaslValue::Null)
}

/// Fills an IP datagram with TCP data. Note that the ip_p field is not updated. It returns the modified IP datagram. Its arguments are:
///  
/// - data: is the TCP data payload.
/// - ip: is the IP datagram to be filled.
/// - th_ack: is the acknowledge number. NASL will convert it into network order if necessary. 0 by default.
/// - th_dport: is the destination port. NASL will convert it into network order if necessary. 0 by default.
/// - th_flags: are the TCP flags. 0 by default.
/// - th_off: is the size of the TCP header in 32 bits words. By default, 5.
/// - th_seq: is the TCP sequence number. NASL will convert it into network order if necessary. Random by default.
/// - th_sport: is the source port. NASL will convert it into network order if necessary. 0 by default.
/// - th_sum: is the TCP checksum. By default, the right value is computed.
/// - th_urp: is the urgent pointer. 0 by default.
/// - th_win: is the TCP window size. NASL will convert it into network order if necessary. 0 by default.
/// - th_x2: is a reserved field and should probably be left unchanged. 0 by default.
/// - update_ip_len: is a flag (TRUE by default). If set, NASL will recompute the size field of the IP datagram.
///  
/// The modified IP datagram or NULL on error.
fn forge_tcp_packet<K>(
    _register: &Register,
    _configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    Ok(NaslValue::Null)
}

/// Get an TCP element from a IP datagram. It returns a data block or an integer, according to the type of the element. Its arguments are:
/// - tcp: is the IP datagram.
/// - element: is the name of the field to get
///   
/// Valid IP elements to get are:
/// - th_sport
/// - th_dsport
/// - th_seq
/// - th_ack
/// - th_x2
/// - th_off
/// - th_flags
/// - th_win
/// - th_sum
/// - th_urp
/// - data
///  
/// Returns an TCP element from a IP datagram.
fn get_tcp_element<K>(
    _register: &Register,
    _configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    Ok(NaslValue::Null)
}

/// Get a TCP option from a IP datagram. Its arguments are:
/// - tcp: is the IP datagram.
/// - option: is the name of the field to get
///   
/// Valid IP options to get are:
/// - 2: TCPOPT_MAXSEG, values between 536 and 65535
/// - 3: TCPOPT_WINDOW, with values between 0 and 14
/// - 4: TCPOPT_SACK_PERMITTED, no value required.
/// - 8: TCPOPT_TIMESTAMP, 8 bytes value for timestamp and echo timestamp, 4 bytes each one.
///  
/// The returned option depends on the given *option* parameter. It is either an int for option 2, 3 and 4 or an array containing the two values for option 8.
fn get_tcp_option<K>(
    _register: &Register,
    _configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    Ok(NaslValue::Null)
}

/// This function modifies the TCP fields of an IP datagram. Its arguments are:
///  
/// - data: is the TCP data payload.
/// - tcp: is the IP datagram to be filled.
/// - th_ack: is the acknowledge number. NASL will convert it into network order if necessary. 0 by default.
/// - th_dport: is the destination port. NASL will convert it into network order if necessary. 0 by default.
/// - th_flags: are the TCP flags. 0 by default.
/// - th_off: is the size of the TCP header in 32 bits words. By default, 5.
/// - th_seq: is the TCP sequence number. NASL will convert it into network order if necessary. Random by default.
/// - th_sport: is the source port. NASL will convert it into network order if necessary. 0 by default.
/// - th_sum: is the TCP checksum. By default, the right value is computed.
/// - th_urp: is the urgent pointer. 0 by default.
/// - th_win: is the TCP window size. NASL will convert it into network order if necessary. 0 by default.
/// - th_x2: is a reserved field and should probably be left unchanged. 0 by default.
/// - update_ip_len: is a flag (TRUE by default). If set, NASL will recompute the size field of the IP datagram.
fn set_tcp_elements<K>(
    _register: &Register,
    _configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    Ok(NaslValue::Null)
}

/// This function adds TCP options to a IP datagram. The options are given as key value(s) pair with the positional argument list. The first positional argument is the identifier of the option, the next positional argument is the value for the option. For the option TCPOPT_TIMESTAMP (8) two values must be given.
///  
/// Available options are:
///  
/// - 2: TCPOPT_MAXSEG, values between 536 and 65535
/// - 3: TCPOPT_WINDOW, with values between 0 and 14
/// - 4: TCPOPT_SACK_PERMITTED, no value required.
/// - 8: TCPOPT_TIMESTAMP, 8 bytes value for timestamp and echo timestamp, 4 bytes each one.
fn insert_tcp_options<K>(
    _register: &Register,
    _configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    Ok(NaslValue::Null)
}

/// Receive a list of IPv4 datagrams and print their TCP part in a readable format in the screen.
fn dump_tcp_packet<K>(
    _register: &Register,
    _configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    Ok(NaslValue::Null)
}

/// Fills an IP datagram with UDP data. Note that the ip_p field is not updated. It returns the modified IP datagram. Its arguments are:
///  
/// - data: is the payload.
/// - ip: is the IP datagram to be filled.
/// - uh_dport: is the destination port. NASL will convert it into network order if necessary. 0 by default.
/// - uh_sport: is the source port. NASL will convert it into network order if necessary. 0 by default.
/// - uh_sum: is the UDP checksum. Although it is not compulsory, the right value is computed by default.
/// - uh_ulen: is the data length. By default it is set to the length the data argument plus the size of the UDP header.
/// - update_ip_len: is a flag (TRUE by default). If set, NASL will recompute the size field of the IP datagram.

/// Returns the modified IP datagram or NULL on error.
fn forge_udp_packet<K>(
    _register: &Register,
    _configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    Ok(NaslValue::Null)
}

/// This function modifies the UDP fields of an IP datagram. Its arguments are:
///  
/// - udp: is the IP datagram to be filled.
/// - data: is the payload.
/// - uh_dport: is the destination port. NASL will convert it into network order if necessary. 0 by default.
/// - uh_sport: is the source port. NASL will convert it into network order if necessary. 0 by default.
/// - uh_sum: is the UDP checksum. Although it is not compulsory, the right value is computed by default.
/// - uh_ulen: is the data length. By default it is set to the length the data argument plus the size of the UDP header.
fn set_udp_elements<K>(
    _register: &Register,
    _configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    Ok(NaslValue::Null)
}

/// Receive a list of IPv4 datagrams and print their UDP part in a readable format in the screen.
fn dump_udp_packet<K>(
    _register: &Register,
    _configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    Ok(NaslValue::Null)
}

/// Get an UDP element from a IP datagram. It returns a data block or an integer, according to the type of the element. Its arguments are:
/// - udp: is the IP datagram.
/// - element: is the name of the field to get
///   
/// Valid IP elements to get are:
/// - uh_sport
/// - uh_dport
/// - uh_ulen
/// - uh_sum
/// - data
fn get_udp_element<K>(
    _register: &Register,
    _configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    Ok(NaslValue::Null)
}

/// Fills an IP datagram with ICMP data. Note that the ip_p field is not updated. It returns the modified IP datagram. Its arguments are:
/// - *ip*: IP datagram that is updated.
/// - *data*: Payload.
/// - *icmp_cksum*: Checksum, computed by default.
/// - *icmp_code*: ICMP code. 0 by default.
/// - *icmp_id*: ICMP ID. 0 by default.
/// - *icmp_seq*: ICMP sequence number.
/// - *icmp_type*: ICMP type. 0 by default.
/// - *update_ip_len*: If this flag is set, NASL will recompute the size field of the IP datagram. Default: True.
fn forge_icmp_packet<K>(
    _register: &Register,
    _configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    Ok(NaslValue::Null)
}

/// Get an ICMP element from a IP datagram. It returns a data block or an integer, according to the type of the element. Its arguments are:
/// - icmp: is the IP datagram (not the ICMP part only).
/// - element: is the name of the field to get
///   
/// Valid ICMP elements to get are:
/// - icmp_id
/// - icmp_code
/// - icmp_type
/// - icmp_seq
/// - icmp_chsum
/// - icmp_data
fn get_icmp_element<K>(
    _register: &Register,
    _configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    Ok(NaslValue::Null)
}

/// Receive a list of IPv4 ICMP packets and print them in a readable format in the screen.
fn dump_icmp_packet<K>(
    _register: &Register,
    _configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    Ok(NaslValue::Null)
}

/// Fills an IP datagram with IGMP data. Note that the ip_p field is not updated. It returns the modified IP datagram. Its arguments are:
/// - ip: IP datagram that is updated.
/// - data: Payload.
/// - code: IGMP code. 0 by default.
/// - group: IGMP group
/// - type: IGMP type. 0 by default.
/// - update_ip_len: If this flag is set, NASL will recompute the size field of the IP datagram. Default: True.
fn forge_igmp_packet<K>(
    _register: &Register,
    _configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    Ok(NaslValue::Null)
}

/// This function tries to open a TCP connection and sees if anything comes back (SYN/ACK or RST).
///  
/// Its argument is:
/// - port: port for the ping
fn nasl_tcp_ping<K>(
    _register: &Register,
    _configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    Ok(NaslValue::Null)
}

/// Send a list of packets, passed as unnamed arguments, with the option to listen to the answers.
///  
/// The arguments are:
/// - Any number of packets to send
/// - length: default length of each every packet, if a packet does not fit, its actual size is taken instead
/// - pcap_active: option to capture the answers, TRUE by default
/// - pcap_filter: BPF filter used for the answers
/// - pcap_timeout: time to wait for the answers in seconds, 5 by default
/// - allow_broadcast: default FALSE
fn nasl_send_packet<K>(
    _register: &Register,
    _configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    Ok(NaslValue::Null)
}

/// This function is the same as send_capture().
///  
/// - interface: network interface name, by default NASL will try to find the best one
/// - pcap_filter: BPF filter, by default it listens to everything
/// - timeout: timeout in seconds, 5 by default
fn nasl_pcap_next<K>(
    _register: &Register,
    _configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    Ok(NaslValue::Null)
}

/// Read the next packet.
///  
/// - interface: network interface name, by default NASL will try to find the best one
/// - pcap_filter: BPF filter, by default it listens to everything
/// - timeout: timeout in seconds, 5 by default
fn nasl_send_capture<K>(
    _register: &Register,
    _configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    Ok(NaslValue::Null)
}

/// Returns found function for key or None when not found
pub fn lookup<K>(key: &str) -> Option<NaslFunction<K>> {
    match key {
        "forge_ip_packet" => Some(forge_ip_packet),
        "set_ip_elements" => Some(set_ip_elements),
        "get_ip_element" => Some(get_ip_element),
        "dump_ip_packet" => Some(dump_ip_packet),
        "insert_ip_options" => Some(insert_ip_options),
        "forge_tcp_packet" => Some(forge_tcp_packet),
        "get_tcp_element" => Some(get_tcp_element),
        "get_tcp_option" => Some(get_tcp_option),
        "set_tcp_elements" => Some(set_tcp_elements),
        "insert_tcp_options" => Some(insert_tcp_options),
        "dump_tcp_packet" => Some(dump_tcp_packet),
        "forge_udp_packet" => Some(forge_udp_packet),
        "set_udp_elements" => Some(set_udp_elements),
        "dump_udp_packet" => Some(dump_udp_packet),
        "get_udp_element" => Some(get_udp_element),
        "forge_icmp_packet" => Some(forge_icmp_packet),
        "get_icmp_element" => Some(get_icmp_element),
        "dump_icmp_packet" => Some(dump_icmp_packet),
        "forge_igmp_packet" => Some(forge_igmp_packet),
        "tcp_ping" => Some(nasl_tcp_ping),
        "send_packet" => Some(nasl_send_packet),
        "pcap_next" => Some(nasl_pcap_next),
        "send_capture" => Some(nasl_send_capture),
        _ => None,
    }
}

#[cfg(test)]
mod tests {

    use crate::{DefaultContext, Interpreter, NaslValue, Register};
    use nasl_syntax::parse;

    #[test]
    fn forge_frame() {
        let code = r###"
        ip_packet = forge_ip_packet(ip_v : 4,
                     ip_hl : 5,
                     ip_tos : 0,
                     ip_len : 20,
                     ip_id : 1234,
                     ip_p : 0x06,
                     ip_ttl : 255,
                     ip_off : 0,
                     ip_src : 192.168.0.1,
                     ip_dst : 192.168.0.12);
        "###;
        let mut register = Register::default();
        let binding = DefaultContext::default();
        let context = binding.as_context();
        let mut interpreter = Interpreter::new(&mut register, &context);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(vec![
                69, 0, 0, 20, 210, 4, 0, 0, 255, 6, 104, 129, 192, 168, 0, 1, 192, 168, 0, 12
            ])))
        );
    }
}
