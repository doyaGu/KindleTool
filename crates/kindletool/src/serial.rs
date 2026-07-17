use crate::devices::{DeviceCatalog, DeviceCode, decode_base32};
use crate::{Error, Result};
use md5::{Digest, Md5};

/// Passwords and model information derived from a Kindle serial number.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SerialInfo {
    /// Recognized device code.
    pub(crate) device: DeviceCode,
    /// Human-readable model name.
    pub(crate) device_name: &'static str,
    /// Whether `KindleTool` considers the model Wario-generation or newer.
    pub(crate) wario_or_newer: bool,
    /// Default eight-character root password.
    pub(crate) root_password: String,
    /// Nine-character recovery/MMC password.
    pub(crate) recovery_password: String,
}

impl SerialInfo {
    /// Recognized device code.
    #[must_use]
    pub const fn device(&self) -> DeviceCode {
        self.device
    }
    /// Human-readable model name.
    #[must_use]
    pub const fn device_name(&self) -> &'static str {
        self.device_name
    }
    /// Whether this model uses the Wario-or-newer password offset.
    #[must_use]
    pub const fn wario_or_newer(&self) -> bool {
        self.wario_or_newer
    }
    /// Default root password.
    #[must_use]
    pub fn root_password(&self) -> &str {
        &self.root_password
    }
    /// Recovery/MMC password.
    #[must_use]
    pub fn recovery_password(&self) -> &str {
        &self.recovery_password
    }
}

/// Derive default Kindle passwords and model information from a 16-character serial number.
pub fn serial_info(serial: &str) -> Result<SerialInfo> {
    if serial.len() != 16 || !serial.is_ascii() || serial.chars().any(char::is_whitespace) {
        return Err(Error::InvalidField {
            field: "serial number",
            message: "must contain exactly 16 non-space ASCII characters".to_owned(),
        });
    }
    let upper = serial.to_ascii_uppercase();
    let device = if matches!(upper.as_bytes().first(), Some(b'B' | b'9')) {
        DeviceCode(
            u16::from_str_radix(&upper[2..4], 16).map_err(|error| Error::InvalidField {
                field: "serial device code",
                message: error.to_string(),
            })?,
        )
    } else {
        DeviceCode(u16::try_from(decode_base32(&upper[3..6])?).map_err(|_| {
            Error::InvalidField {
                field: "serial device code",
                message: "value exceeds u16".to_owned(),
            }
        })?)
    };
    let record = DeviceCatalog::by_code(device).ok_or_else(|| Error::InvalidField {
        field: "serial device code",
        message: format!(
            "unknown device {} (0x{:03X})",
            device.serial_code(),
            device.0
        ),
    })?;

    let mut digest = Md5::new();
    digest.update(upper.as_bytes());
    digest.update(b"\n");
    let hash = format!("{:x}", digest.finalize());
    let wario_or_newer = matches!(device.0, 0x13 | 0x17) || device.0 >= 0x2A;
    let offset = if wario_or_newer { 13 } else { 7 };
    Ok(SerialInfo {
        device,
        device_name: record.name,
        wario_or_newer,
        root_password: format!("fiona{}", &hash[offset..offset + 3]),
        recovery_password: format!("fiona{}", &hash[offset..offset + 4]),
    })
}

#[cfg(test)]
mod tests {
    use super::serial_info;

    #[test]
    fn known_pw3_serial_vector_is_stable() {
        let info = serial_info("G090G1XXXXXXXXXX").unwrap();
        assert_eq!(info.root_password, "fionad14");
        assert_eq!(info.recovery_password, "fionad146");
    }
}
