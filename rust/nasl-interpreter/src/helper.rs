// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{fmt::Write, net::IpAddr, num::ParseIntError, str::FromStr};

use crate::{error::FunctionErrorKind, NaslValue};

pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

pub fn encode_hex(bytes: &[u8]) -> Result<String, FunctionErrorKind> {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b)?;
    }
    Ok(s)
}

/// Convert a string in a IpAddr
pub fn ipstr2ipaddr(ip_addr: &str) -> Result<IpAddr, FunctionErrorKind> {
    match IpAddr::from_str(ip_addr) {
        Ok(ip) => Ok(ip),
        Err(_) => Err(FunctionErrorKind::Diagnostic(
            "Invalid IP address".to_string(),
            Some(NaslValue::Null),
        )),
    }
}
