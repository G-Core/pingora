// Copyright 2026 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::*;
use bytes::Bytes;
use http::header;

#[derive(Debug, Clone)]
pub struct CaseHeaderName(Bytes);

impl CaseHeaderName {
    pub fn new(name: String) -> Self {
        CaseHeaderName(name.into())
    }
}

impl CaseHeaderName {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn from_slice(buf: &[u8]) -> Self {
        CaseHeaderName(Bytes::copy_from_slice(buf))
    }

    pub fn from_static(buf: &'static [u8]) -> Self {
        CaseHeaderName(Bytes::from_static(buf))
    }
}

/// A wire-case header name and its parsed form declared together, so an
/// insert/append reuses the parse instead of decoding the bytes each time.
pub struct HeaderNameConstant {
    wire: &'static str,
    name: HeaderName,
}

impl HeaderNameConstant {
    /// Declare a wire-case header name and its already-parsed lowercase form.
    /// The pair is rejected at compile time unless `wire` is a valid header
    /// name whose lowercase form is `parsed`.
    ///
    /// ```compile_fail,E0080
    /// use pingora_http::HeaderNameConstant;
    ///
    /// static BAD: HeaderNameConstant = HeaderNameConstant::new("X-Test", "x-other");
    /// ```
    ///
    /// ```compile_fail,E0080
    /// use pingora_http::HeaderNameConstant;
    ///
    /// static BAD: HeaderNameConstant = HeaderNameConstant::new("X-Test", "x-best");
    /// ```
    pub const fn new(wire: &'static str, parsed: &'static str) -> Self {
        assert!(
            wire_bytes_are_valid_header_name(wire.as_bytes()),
            "HeaderNameConstant wire bytes are not a valid header name"
        );
        assert!(
            wire_case_matches(wire.as_bytes(), parsed.as_bytes()),
            "HeaderNameConstant wire and parsed names differ"
        );
        Self {
            wire,
            name: HeaderName::from_static(parsed),
        }
    }

    /// The parsed lowercase name used as the header-map key.
    pub fn name(&self) -> &HeaderName {
        &self.name
    }

    /// The declared HTTP/1 wire spelling, as bytes.
    pub fn wire(&self) -> &'static [u8] {
        self.wire.as_bytes()
    }

    /// The declared HTTP/1 wire spelling, as a string.
    pub fn wire_str(&self) -> &'static str {
        self.wire
    }
}

const fn wire_case_matches(wire: &[u8], parsed: &[u8]) -> bool {
    if wire.len() != parsed.len() {
        return false;
    }
    let mut i = 0;
    while i < wire.len() {
        if !wire[i].eq_ignore_ascii_case(&parsed[i]) {
            return false;
        }
        i += 1;
    }
    true
}

// RFC 9110 token characters.
const fn wire_bytes_are_valid_header_name(wire: &[u8]) -> bool {
    if wire.is_empty() {
        return false;
    }
    let mut i = 0;
    while i < wire.len() {
        if !matches!(
            wire[i],
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
                | b'0'..=b'9'
                | b'a'..=b'z'
                | b'A'..=b'Z'
        ) {
            return false;
        }
        i += 1;
    }
    true
}

/// A trait that converts into case-sensitive header names.
pub trait IntoCaseHeaderName {
    fn into_case_header_name(self) -> CaseHeaderName;

    /// The already-parsed name, when this value carries one.
    fn parsed_header_name(&self) -> Option<HeaderName> {
        None
    }
}

impl IntoCaseHeaderName for &HeaderNameConstant {
    fn into_case_header_name(self) -> CaseHeaderName {
        CaseHeaderName::from_static(self.wire.as_bytes())
    }

    fn parsed_header_name(&self) -> Option<HeaderName> {
        Some(self.name.clone())
    }
}

impl IntoCaseHeaderName for CaseHeaderName {
    fn into_case_header_name(self) -> CaseHeaderName {
        self
    }
}

impl IntoCaseHeaderName for String {
    fn into_case_header_name(self) -> CaseHeaderName {
        CaseHeaderName(self.into())
    }
}

impl IntoCaseHeaderName for &'static str {
    fn into_case_header_name(self) -> CaseHeaderName {
        CaseHeaderName(self.into())
    }
}

impl IntoCaseHeaderName for HeaderName {
    fn into_case_header_name(self) -> CaseHeaderName {
        CaseHeaderName(titled_header_name(&self))
    }

    fn parsed_header_name(&self) -> Option<HeaderName> {
        Some(self.clone())
    }
}

impl IntoCaseHeaderName for &HeaderName {
    fn into_case_header_name(self) -> CaseHeaderName {
        CaseHeaderName(titled_header_name(self))
    }

    fn parsed_header_name(&self) -> Option<HeaderName> {
        Some((*self).clone())
    }
}

impl IntoCaseHeaderName for Bytes {
    fn into_case_header_name(self) -> CaseHeaderName {
        CaseHeaderName(self)
    }
}

fn titled_header_name(header_name: &HeaderName) -> Bytes {
    titled_header_name_str(header_name).map_or_else(
        || Bytes::copy_from_slice(header_name.as_str().as_bytes()),
        |s| Bytes::from_static(s.as_bytes()),
    )
}

pub(crate) fn titled_header_name_str(header_name: &HeaderName) -> Option<&'static str> {
    Some(match *header_name {
        header::ACCEPT_RANGES => "Accept-Ranges",
        header::AGE => "Age",
        header::CACHE_CONTROL => "Cache-Control",
        header::CONNECTION => "Connection",
        header::CONTENT_TYPE => "Content-Type",
        header::CONTENT_ENCODING => "Content-Encoding",
        header::CONTENT_LENGTH => "Content-Length",
        header::DATE => "Date",
        header::TRANSFER_ENCODING => "Transfer-Encoding",
        header::HOST => "Host",
        header::SERVER => "Server",
        header::SET_COOKIE => "Set-Cookie",
        // TODO: add more const header here to map to their titled case
        // TODO: automatically upper case the first letter?
        _ => {
            return None;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_case_header_name() {
        assert_eq!("FoO".into_case_header_name().as_slice(), b"FoO");
        assert_eq!("FoO".to_string().into_case_header_name().as_slice(), b"FoO");
        assert_eq!(header::SERVER.into_case_header_name().as_slice(), b"Server");
    }

    #[test]
    fn header_name_constant_rejects_a_mismatched_pair() {
        assert!(wire_case_matches(b"X-Test", b"x-test"));
        assert!(!wire_case_matches(b"X-Test", b"x-other"));
        assert!(!wire_case_matches(b"X-Test", b"x-test-2"));
    }

    #[test]
    fn header_name_constant_rejects_invalid_wire_bytes() {
        assert!(wire_bytes_are_valid_header_name(b"X-Test"));
        for invalid in [&b""[..], b"X Test", b"X-Test\r\n", b"\xff"] {
            assert!(
                !wire_bytes_are_valid_header_name(invalid),
                "{invalid:?} must not be a valid wire header name"
            );
        }
    }

    #[test]
    fn pre_parsed_constant_serializes_like_a_string_name() {
        static X_TEST: HeaderNameConstant = HeaderNameConstant::new("X-Test-Name", "x-test-name");

        fn request(keep_case: bool) -> crate::RequestHeader {
            if keep_case {
                crate::RequestHeader::build("GET", b"/", None).unwrap()
            } else {
                crate::RequestHeader::build_no_case("GET", b"/", None).unwrap()
            }
        }

        fn wire(req: &crate::RequestHeader) -> bytes::BytesMut {
            let mut buf = bytes::BytesMut::new();
            req.header_to_h1_wire(&mut buf);
            buf
        }

        for keep_case in [true, false] {
            let mut via_constant = request(keep_case);
            let mut via_string = request(keep_case);

            via_constant.insert_header(&X_TEST, "one").unwrap();
            via_string.insert_header("X-Test-Name", "one").unwrap();
            assert_eq!(wire(&via_constant), wire(&via_string), "insert {keep_case}");

            via_constant.append_header(&X_TEST, "two").unwrap();
            via_string.append_header("X-Test-Name", "two").unwrap();
            assert_eq!(wire(&via_constant), wire(&via_string), "append {keep_case}");

            via_constant.remove_header(X_TEST.name());
            via_string.remove_header("X-Test-Name");
            assert_eq!(wire(&via_constant), wire(&via_string), "remove {keep_case}");
            assert!(via_constant.headers.get(X_TEST.name()).is_none());
        }
    }
}
