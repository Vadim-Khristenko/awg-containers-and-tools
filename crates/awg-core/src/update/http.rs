//! The only socket this crate opens.
//!
//! `curl`, then `wget`, run as processes with their arguments passed directly —
//! never through a shell.
//!
//! Adding an HTTP client to `awg-core` would drag a TLS stack and an async
//! runtime into a crate that also compiles to WASM, for two requests that are
//! both optional. A host with neither tool gets an `Unknown` verdict from the
//! callers in [`super::github`] and [`super::registry`], which is a correct
//! answer rather than a failure.

use std::process::Command;

use super::version::CURRENT_VERSION;
use crate::{Error, Result};

/// How long any single request is allowed to take. Short on purpose: this runs
/// alongside something the user actually asked for.
pub const HTTP_TIMEOUT_SECS: u32 = 10;

/// Fetch a URL as text. Plain HTTP is refused.
pub fn http_get(url: &str) -> Result<String> {
    if !url.starts_with("https://") {
        return Err(Error::Config(format!(
            "refusing to fetch {url} over plain HTTP"
        )));
    }
    let agent = format!("awg-tool/{CURRENT_VERSION}");
    let timeout = HTTP_TIMEOUT_SECS.to_string();

    match Command::new("curl")
        .args([
            "-fsSL",
            "--max-time",
            &timeout,
            "-H",
            "Accept: application/json",
            "-A",
            &agent,
            url,
        ])
        .output()
    {
        Ok(o) if o.status.success() => return Ok(String::from_utf8_lossy(&o.stdout).into_owned()),
        Ok(o) => {
            // curl ran and was refused: that is an answer, not a reason to try
            // a second client and get the same refusal.
            let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
            return Err(Error::Config(format!(
                "curl could not fetch {url}: {}",
                if err.is_empty() {
                    format!("exit {}", o.status)
                } else {
                    err
                }
            )));
        }
        // curl is not installed; fall through.
        Err(_) => {}
    }

    let wget = Command::new("wget")
        .args([
            "-qO-",
            "--timeout",
            &timeout,
            "--header=Accept: application/json",
            "-U",
            &agent,
            url,
        ])
        .output()
        .map_err(|e| Error::Config(format!("neither curl nor wget is usable here: {e}")))?;
    if wget.status.success() {
        Ok(String::from_utf8_lossy(&wget.stdout).into_owned())
    } else {
        Err(Error::Config(format!(
            "wget could not fetch {url}: exit {}",
            wget.status
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_http_is_refused_without_a_request_being_made() {
        let e = http_get("http://example.com/x").unwrap_err();
        assert!(e.to_string().contains("plain HTTP"));
        assert!(http_get("ftp://example.com").is_err());
        assert!(http_get("").is_err());
    }
}
