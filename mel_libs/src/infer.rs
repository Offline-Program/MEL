//! Inference host configuration for the RHOKP chat assistant.

use crate::assistant::assistant_enabled;
use crate::error::MelError;
use serde::Serialize;
use std::{env::VarError, fs, path::Path, sync::OnceLock};
use url::Url;

/// The name of the environment variable used to provide an inference service URL to RHOKP's chat
/// assistant.
const INFERENCE_URL_ENV: &str = "INFERENCE_URL";

/// Get the inference URL which the RHOKP chat assistant can connect to, if one is configured. The
/// value is read from the INFERENCE_URL environment variable.
pub fn inference_url() -> Result<&'static Option<Url>, &'static MelError> {
    static INFERENCE_URL: OnceLock<Result<Option<Url>, MelError>> = OnceLock::new();
    INFERENCE_URL
        .get_or_init(|| {
            let url_env = match std::env::var(INFERENCE_URL_ENV) {
                Ok(raw) => raw,
                // A missing INFERENCE_URL is okay (it's required if OFFLINE_VIRTUAL_ASSISTANT is
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

/// A struct representing the inference.json file that is written to allow the Offline Virtual
/// Assistant knows what inference server to talk to.
#[derive(Serialize)]
struct Inference<'a> {
    /// The URL of the Lightspeed Stack (or other) inference server.
    url: &'a Url,
}

/// Write a JSON file containing the inference URL into the webroot, for the Offline Virtual
/// Assistant to read.
pub fn write_inference_url(url: &Url, base_path: &Path) -> Result<(), MelError> {
    let inf = Inference { url };
    let inference_url_json_path = base_path.join("inference.json");
    let json = serde_json::to_string_pretty(&inf).map_err(|_e| MelError::InferenceUrlWrite)?;
    fs::write(inference_url_json_path, json).map_err(|_e| MelError::InferenceUrlWrite)?;
    Ok(())
}

/// Handle initializing the inference.json file, including conditions and errors.  The file will
/// only be written if the OFFLINE_VIRTUAL_ASSISTANT environment variable is set and an
/// INFERENCE_URL is provided.
pub fn init_inference() -> Result<(), MelError> {
    match (
        assistant_enabled(),
        inference_url().map_err(|_| MelError::InferenceUrlInvalid)?,
    ) {
        (true, Some(url)) => {
            write_inference_url(url, Path::new("/var/www/html/virtual-assistant/api/"))
        }
        (false, Some(_)) => Err(MelError::InferenceUrlNoAssistant),
        (true, None) => Err(MelError::AssistantNoInferenceUrl),
        (_, None) => Ok(()),
    }
}
