//! Inference host configuration for Ask Red Hat Offline, the RHOKP conversational search.

use crate::ask::ask_enabled;
use crate::error::MelError;
use serde::Serialize;
use std::{env::VarError, fs, path::Path, sync::OnceLock};
use url::Url;

/// The name of the environment variable used to provide an inference service URL to RHOKP's
/// conversational search.
pub const INFERENCE_URL_ENV: &str = "INFERENCE_URL";

/// Get the inference URL which the RHOKP conversational search can connect to, if one is
/// configured. The value is read from the INFERENCE_URL environment variable.
pub fn inference_url() -> Result<&'static Option<Url>, &'static MelError> {
    static INFERENCE_URL: OnceLock<Result<Option<Url>, MelError>> = OnceLock::new();
    INFERENCE_URL
        .get_or_init(|| {
            let url_env = match std::env::var(INFERENCE_URL_ENV) {
                Ok(raw) => raw,
                // A missing INFERENCE_URL is okay (it's required if ASK_RED_HAT_OFFLINE is
                // provided, but that logic is handled elsewhere).
                Err(VarError::NotPresent) => return Ok(None),
                // Treat non-unicode strings as invalid URLs.
                Err(VarError::NotUnicode(_)) => return Err(MelError::InferenceUrlInvalid),
            };

            let Ok(url) = Url::parse(&url_env) else {
                return Err(MelError::InferenceUrlInvalid);
            };

            Ok(Some(url))
        })
        .as_ref()
}

/// A struct representing the inference.json file that is written into the container's default
/// user's homedir, so that Ask Red Hat Offline can know what inference server to talk to.
#[derive(Serialize)]
struct Inference<'a> {
    /// The URL of the Lightspeed Stack (or other) inference server.
    url: &'a Url,
}

/// Write a JSON file containing the inference URL into the `base_path`, for Ask Red Hat Offline to
/// read.
fn write_inference_url(url: &Url, base_path: &Path) -> Result<(), MelError> {
    let inf = Inference { url };
    let inference_url_json_path = base_path.join("inference.json");
    let json = serde_json::to_string_pretty(&inf).map_err(|_e| MelError::InferenceUrlWrite)?;
    fs::write(inference_url_json_path, json).map_err(|_e| MelError::InferenceUrlWrite)?;
    Ok(())
}

/// Handle initializing the inference.json file, including conditions and errors.  The file will
/// only be written if the ASK_RED_HAT_OFFLINE environment variable is set and an INFERENCE_URL is
/// provided.
pub fn init_inference() -> Result<(), MelError> {
    let inf_url = match inference_url() {
        Ok(url) => url,
        Err(e) => return Err(*e),
    };
    match (ask_enabled(), inf_url) {
        (true, Some(url)) => write_inference_url(url, Path::new("/opt/app-root/src/")),
        (false, Some(_)) => Err(MelError::InferenceUrlButNoAsk),
        (true, None) => Err(MelError::AskButNoInferenceUrl),
        (false, None) => Ok(()),
    }
}
