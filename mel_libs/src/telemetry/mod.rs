// Mimir Encrypted Launcher & supporting libraries
// Copyright (C) 2025  Red Hat, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

// #![warn(clippy::missing_docs_in_private_items, missing_docs)]

//! Telemetry related functionality.

use nom::{
    bytes::complete::tag,
    character::complete::{char, space1, u16},
    combinator::{map, map_opt},
    error::{Error, ErrorKind},
    sequence::{delimited, preceded},
    Err, IResult,
};
use serde::Serialize;

/// Represents a single parsed log entry.
#[derive(Debug, PartialEq, Serialize)]
pub struct LogEntry<'a> {
    pub timestamp_epoch_ms: &'a str,
    pub user_agent: Option<&'a str>,
    pub hostname: &'a str,
    pub url_path: Option<&'a str>,
    pub http_req_first_line: Option<&'a str>,
    pub filename: Option<&'a str>,
    pub http_final_status: u16,
    pub res_size_bytes: Option<u64>,
    pub res_serve_time_microseconds: Option<u64>,
}

fn parse_balanced_brackets(input: &str) -> IResult<&str, &str> {
    let mut depth = 1;
    let mut end_index = None;

    for (i, c) in input.char_indices() {
        match c {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    end_index = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }

    match end_index {
        Some(i) => {
            let (value, rest) = input.split_at(i);
            Ok((&rest[1..], value))
        }
        None => Err(Err::Error(Error::new(input, ErrorKind::TakeUntil))),
    }
}

fn parse_required_str<'a>(key: &'a str) -> impl FnMut(&'a str) -> IResult<&'a str, &'a str> {
    preceded(tag(key), preceded(char('['), parse_balanced_brackets))
}

/// Parse a `key=[value]` pair where the value is a required (non-Optional) string.
fn parse_required_timestamp<'a>() -> impl FnMut(&'a str) -> IResult<&'a str, &'a str> {
    preceded(
        tag("timestamp_epoch_ms="),
        preceded(char('['), parse_balanced_brackets),
    )
}

/// Parse a `key=[value]` pair where the value is an optional string.  The value `-` from Apache is
/// given when no value exists, and is interpreted here as None.
fn parse_optional_str<'a>(
    key: &'a str,
) -> impl FnMut(&'a str) -> IResult<&'a str, Option<&'a str>> {
    map(parse_required_str(key), |s: &str| {
        if s == "-" {
            None
        } else {
            Some(s)
        }
    })
}

/// Parse a `key=[value]` pair where the value is a required (non-Optional) u16.
fn parse_required_u16<'a>(key: &'a str) -> impl FnMut(&'a str) -> IResult<&'a str, u16> {
    preceded(tag(key), delimited(char('['), u16, char(']')))
}

/// Parse a `key=[value]` pair where the value is a required (non-Optional) u64.
fn parse_optional_u64<'a>(key: &'a str) -> impl FnMut(&'a str) -> IResult<&'a str, Option<u64>> {
    map_opt(parse_required_str(key), |s: &str| {
        if s == "-" {
            Some(None)
        } else {
            s.parse::<u64>().ok().map(Some)
        }
    })
}

/// Parse a line from the RHOKP telemetry log format.
pub fn parse_line(input: &str) -> IResult<&str, LogEntry> {
    // The log entries must be in this specific order.
    // TODO: relax the ordering requirement
    let (input, timestamp_epoch_ms) = parse_required_timestamp()(input)?;
    let (input, _) = space1(input)?;

    let (input, user_agent) = parse_optional_str("user_agent=")(input)?;
    let (input, _) = space1(input)?;

    let (input, hostname) = parse_required_str("hostname=")(input)?;
    let (input, _) = space1(input)?;

    let (input, url_path) = parse_optional_str("url_path=")(input)?;
    let (input, _) = space1(input)?;

    let (input, http_req_first_line) = parse_optional_str("http_req_first_line=")(input)?;
    let (input, _) = space1(input)?;

    let (input, filename) = parse_optional_str("filename=")(input)?;
    let (input, _) = space1(input)?;

    let (input, http_final_status) = parse_required_u16("http_final_status=")(input)?;
    let (input, _) = space1(input)?;

    let (input, res_size_bytes) = parse_optional_u64("res_size_bytes=")(input)?;
    let (input, _) = space1(input)?;

    let (input, res_serve_time_microseconds) =
        parse_optional_u64("res_serve_time_microseconds=")(input)?;

    let entry = LogEntry {
        timestamp_epoch_ms,
        user_agent,
        hostname,
        url_path,
        http_req_first_line,
        filename,
        http_final_status,
        res_size_bytes,
        res_serve_time_microseconds,
    };

    Ok((input, entry))
}

#[cfg(test)]
mod tests {
    use nom::combinator::all_consuming;

    use super::*;

    #[test]
    fn test_parse_example_line() {
        let log_line = "timestamp_epoch_ms=[1757956637250] user_agent=[-] hostname=[192.168.1.163] url_path=[/index.html] http_req_first_line=[GET /index.html HTTP/1.1] filename=[/var/www/html/index.html] http_final_status=[408] res_size_bytes=[-] res_serve_time_microseconds=[45]";
        let (_, entry) = all_consuming(parse_line)(log_line).unwrap();

        assert_eq!(
            entry,
            LogEntry {
                timestamp_epoch_ms: "1757956637250",
                user_agent: None,
                hostname: "192.168.1.163",
                url_path: Some("/index.html"),
                http_req_first_line: Some("GET /index.html HTTP/1.1"),
                filename: Some("/var/www/html/index.html"),
                http_final_status: 408,
                res_size_bytes: None,
                res_serve_time_microseconds: Some(45),
            }
        );
    }

    #[test]
    fn test_parse_line_with_nested_brackets() {
        let log_line = "timestamp_epoch_ms=[[15/Sep/2025:14:38:11 +0000]] user_agent=[curl[]/7.88.1] hostname=[foo] url_path=[-] http_req_first_line=[-] filename=[-] http_final_status=[200] res_size_bytes=[-] res_serve_time_microseconds=[10]";
        let (_, entry) = all_consuming(parse_line)(log_line).unwrap();
        assert_eq!(entry.user_agent, Some("curl[]/7.88.1"));
    }

    #[test]
    fn test_parse_line_with_deeply_nested_brackets() {
        let log_line = "timestamp_epoch_ms=[[...]] user_agent=[a[b[c]d]e] hostname=[foo] url_path=[-] http_req_first_line=[-] filename=[-] http_final_status=[200] res_size_bytes=[-] res_serve_time_microseconds=[10]";
        let (_, entry) = all_consuming(parse_line)(log_line).unwrap();
        assert_eq!(entry.user_agent, Some("a[b[c]d]e"));
    }

    #[test]
    fn test_unbalanced_brackets_fails() {
        let log_line = "timestamp_epoch_ms=[[...]] user_agent=[a[b[c]d] hostname=[foo] url_path=[-] http_req_first_line=[-] filename=[-] http_final_status=[200] res_size_bytes=[-] res_serve_time_microseconds=[10]";
        assert!(all_consuming(parse_line)(log_line).is_err());
    }

    #[test]
    fn test_early_closing_bracket_fails() {
        let log_line = "timestamp_epoch_ms=[[...]] user_agent=[abc]d] hostname=[foo] url_path=[-] http_req_first_line=[-] filename=[-] http_final_status=[200] res_size_bytes=[-] res_serve_time_microseconds=[10]";
        assert!(all_consuming(parse_line)(log_line).is_err());
    }
}
