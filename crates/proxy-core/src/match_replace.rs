//! Match & replace: replacement rules on requests/responses, applied on the proxy path.
//! A shared handle (`Arc<RwLock>`) — writes swap the rule set at runtime,
//! reads on the hot relay path. Literal (substring) replacement, by bytes in the body and by
//! strings in the request-line/headers.
use std::sync::{Arc, RwLock};

use http_model::{HttpRequest, HttpResponse, MatchReplaceRule};

/// A shared set of match & replace rules.
#[derive(Clone, Default)]
pub struct MatchReplace {
    rules: Arc<RwLock<Vec<MatchReplaceRule>>>,
}

impl MatchReplace {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&self, rules: Vec<MatchReplaceRule>) {
        *self.rules.write().expect("match-replace lock") = rules;
    }

    pub fn get(&self) -> Vec<MatchReplaceRule> {
        self.rules.read().expect("match-replace lock").clone()
    }

    /// Applies the `on_request` rules to the request (in-place).
    pub fn apply_request(&self, req: &mut HttpRequest) {
        let rules = self.rules.read().expect("match-replace lock");
        for rule in rules
            .iter()
            .filter(|r| r.on_request && !r.match_pattern.is_empty())
        {
            let (pat, rep) = (&rule.match_pattern, &rule.replace_with);
            req.method = req.method.replace(pat, rep);
            req.target = req.target.replace(pat, rep);
            for h in &mut req.headers {
                h.name = h.name.replace(pat, rep);
                h.value = h.value.replace(pat, rep);
            }
            req.body = replace_bytes(&req.body, pat.as_bytes(), rep.as_bytes());
        }
    }

    /// Applies the `on_response` rules to the response (in-place).
    pub fn apply_response(&self, resp: &mut HttpResponse) {
        let rules = self.rules.read().expect("match-replace lock");
        for rule in rules
            .iter()
            .filter(|r| r.on_response && !r.match_pattern.is_empty())
        {
            let (pat, rep) = (&rule.match_pattern, &rule.replace_with);
            for h in &mut resp.headers {
                h.name = h.name.replace(pat, rep);
                h.value = h.value.replace(pat, rep);
            }
            resp.body = replace_bytes(&resp.body, pat.as_bytes(), rep.as_bytes());
        }
    }
}

fn replace_bytes(body: &[u8], pattern: &[u8], replacement: &[u8]) -> Vec<u8> {
    if pattern.is_empty() {
        return body.to_vec();
    }
    let mut out = Vec::with_capacity(body.len());
    let mut i = 0;
    while i < body.len() {
        if body[i..].starts_with(pattern) {
            out.extend_from_slice(replacement);
            i += pattern.len();
        } else {
            out.push(body[i]);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_model::{Header, HttpRequest, HttpResponse};

    fn rule(pat: &str, rep: &str, on_request: bool, on_response: bool) -> MatchReplaceRule {
        MatchReplaceRule {
            name: "t".to_owned(),
            match_pattern: pat.to_owned(),
            replace_with: rep.to_owned(),
            on_request,
            on_response,
        }
    }

    #[test]
    fn request_rules_rewrite_target_headers_body_only_when_on_request() {
        let mr = MatchReplace::new();
        mr.set(vec![rule("foo", "bar", true, false)]);
        let mut req = HttpRequest {
            method: "GET".to_owned(),
            target: "http://h/foo".to_owned(),
            version: "HTTP/1.1".to_owned(),
            headers: vec![Header {
                name: "x-foo".to_owned(),
                value: "foo".to_owned(),
            }],
            body: b"foo body".to_vec(),
            raw: false,
        };
        mr.apply_request(&mut req);
        assert_eq!(req.target, "http://h/bar");
        assert_eq!(req.headers[0].name, "x-bar");
        assert_eq!(req.headers[0].value, "bar");
        assert_eq!(req.body, b"bar body");
    }

    #[test]
    fn response_only_rule_does_not_touch_request() {
        let mr = MatchReplace::new();
        mr.set(vec![rule("foo", "bar", false, true)]);
        let mut req = HttpRequest {
            method: "GET".to_owned(),
            target: "http://h/foo".to_owned(),
            version: "HTTP/1.1".to_owned(),
            headers: Vec::new(),
            body: b"foo".to_vec(),
            raw: false,
        };
        mr.apply_request(&mut req);
        assert_eq!(req.target, "http://h/foo"); // untouched

        let mut resp = HttpResponse {
            status: 200,
            version: "HTTP/1.1".to_owned(),
            headers: vec![Header {
                name: "server".to_owned(),
                value: "foo-srv".to_owned(),
            }],
            body: b"hello foo".to_vec(),
        };
        mr.apply_response(&mut resp);
        assert_eq!(resp.headers[0].value, "bar-srv");
        assert_eq!(resp.body, b"hello bar");
    }

    #[test]
    fn empty_pattern_is_noop() {
        let mr = MatchReplace::new();
        mr.set(vec![rule("", "x", true, true)]);
        let mut req = HttpRequest {
            method: "GET".to_owned(),
            target: "http://h/".to_owned(),
            version: "HTTP/1.1".to_owned(),
            headers: Vec::new(),
            body: b"body".to_vec(),
            raw: false,
        };
        mr.apply_request(&mut req);
        assert_eq!(req.body, b"body");
        assert_eq!(req.target, "http://h/");
    }
}
