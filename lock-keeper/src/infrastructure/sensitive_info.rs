//! This defines data types related to the configuration for sensitive information handling.

use std::convert::From;
use tracing::{error};
use crate::crypto::CryptoError;

use zeroize::{Zeroize, ZeroizeOnDrop};
use serde::{Deserialize, Serialize};

/// The [`SensitiveInfoConfig`] type is used to configure how we handle
/// sensitive information such as cryptographic keys, passwords, etc.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct SensitiveInfoConfig {
    /// A boolean indicating whether sensitive information should be redacted.
    ///     If set to true, the sensitive information will be redacted (hidden or masked).
    ///     If set to false, the sensitive information will not be redacted.    
    redact_sensitive_info: bool,
}

/// Conversion from `Vec<u8>` to [`SensitiveInfoConfig`]
impl From<Vec<u8>> for SensitiveInfoConfig {

    fn from(bytes: Vec<u8>) -> Self {
        let config: SensitiveInfoConfig = bincode::deserialize(&bytes).unwrap();
        config
    }
}

/// Conversion from [`SensitiveInfoConfig`] to `Vec<u8>`
impl From<SensitiveInfoConfig> for Vec<u8> {

    fn from(config: SensitiveInfoConfig) -> Self {
        let encoded: Vec<u8> = bincode::serialize(&config).unwrap();
        encoded
    }
}

impl SensitiveInfoConfig {

    /// Tis is the label used to redact sensitive information in the library output
    const REDACTED_INFO_LABEL: &str = "***REDACTED***";

    /// Constructor for [`SensitiveInfoConfig`] type.
    /// The default is to redact sensitive information in the output.
    // pub fn new() -> Self {

    //     Self {redact_sensitive_info: true}
    // }

    /// Constructs a new instance of the type [`SensitiveInfoConfig`]
    ///
    /// # Arguments
    ///
    /// * `redact_sensitive_info`   - A boolean indicating whether to redact sensitive information. 
    ///                             - When set to true, any sensitive information handled by instances using this configuration 
    ///                               will be redacted (hidden or masked). 
    ///                             - When set to false, the sensitive information will not be redacted.
    ///
    /// # Returns
    ///
    /// * Returns a new instance of [`SensitiveInfoConfig`], initialized with the provided `redact_sensitive_info` flag.
    ///
    /// # Example
    ///
    /// ```rust
    /// use lock_keeper::infrastructure::sensitive_info::SensitiveInfoConfig;
    /// let redact_sensitive_info = true;
    /// let config = SensitiveInfoConfig::new(redact_sensitive_info);
    /// ```
    pub fn new(redact_sensitive_info: bool) -> Self {

        Self {
            redact_sensitive_info: redact_sensitive_info,
        }
    }
    

    /// Returns a label that is used in place of sensitive information.
    pub fn redacted_label(self:Self) -> String {
        SensitiveInfoConfig::REDACTED_INFO_LABEL.to_string()
    }

    /// Redact sensitive information.
    pub fn redact(&mut self) {

        self.redact_sensitive_info = true;
    }

    /// Unredact sensitive information.
    pub fn unredact(&mut self) {

        self.redact_sensitive_info = false;
    }

    /// Returns the status of the sensitive information redaction.
    pub fn is_redacted(&self) -> bool {

        self.redact_sensitive_info
    }
}

/// Checks if sensitive information is properly redacted in Debug and Display outputs.
///
/// This function takes a generic `sensitive_info` object and a `config` object 
/// which provides the redaction configuration. 
/// 
/// The `sensitive_info` object should implement the `Debug` and `Display` traits so that it can be 
/// properly formatted for output. 
/// 
/// The function checks if the redaction is correctly applied based on the configuration and the build type (Release or Debug).
///
/// # Arguments
///
/// * `sensitive_info` - A reference to an object of any type that implements `Debug` and `Display`.
/// * `config` - A reference to a [`SensitiveInfoConfig`] object which provides the redaction configuration.
///
/// # Returns
///
/// * `Ok(())` - If the sensitive information is correctly redacted in both Debug and Display outputs.
/// * `Err(CryptoError::SensitiveInfoCheckFailed)` - If the sensitive information is not correctly redacted.
///
/// # Panics
///
/// This function does not panic. However, the caller should handle the [`Err`] result 
/// appropriately.
/// 
pub fn sensitive_info_check<T: std::fmt::Debug + std::fmt::Display> (
    sensitive_info: &T, 
    config: &SensitiveInfoConfig
    
) -> Result<(), CryptoError> {

    // create formatted strings for Debug and Display traits
    let debug_format_sensitive_info = format!("{:?}", sensitive_info);
    let display_format_sensitive_info = format!("{}", sensitive_info);

    // should_be_redacted...
    //      if this is a Release build OR if the redacted config flag is set to true
    let should_be_redacted = !cfg!(debug_assertions) || (config.is_redacted());

    // check if output contains the redacted tag
    let is_debug_redacted = debug_format_sensitive_info.contains(&config.clone().redacted_label());
    let is_display_redacted = display_format_sensitive_info.contains(&config.clone().redacted_label());

    // check if the redacted tag is applied correctly for Debug and Display traits.
    if is_debug_redacted != should_be_redacted {

        error!("Unexpected debug output: {}",
        if should_be_redacted { "Found UN-REDACTED info!!!" } else { "Found REDACTED info." });

        return Err(CryptoError::SensitiveInfoCheckFailed);
    }

    if is_display_redacted != should_be_redacted {

        error!("Unexpected display output: {}",
        if should_be_redacted { "Found UN-REDACTED info!!!" } else { "Found REDACTED info." });

        return Err(CryptoError::SensitiveInfoCheckFailed);
    }

    Ok(())
}
