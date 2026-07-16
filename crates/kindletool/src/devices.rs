use crate::{Error, Result};
use std::fmt;

const BASE32: &[u8; 32] = b"0123456789ABCDEFGHJKLMNPQRSTUVWX";

/// Raw Kindle device code stored in update headers.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DeviceCode(pub u16);

impl DeviceCode {
    /// Encode the code as the serial-number device identifier.
    #[must_use]
    pub fn serial_code(self) -> String {
        if self.0 <= 0xFF {
            format!("{:02X}", self.0)
        } else {
            encode_base32(u32::from(self.0), 3)
        }
    }
}

impl fmt::Display for DeviceCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.serial_code())
    }
}

/// Product family used to derive CLI aliases from the device catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DeviceFamily {
    /// Kindle 1 through Kindle 3 and unclassified identifiers.
    Legacy,
    /// Kindle 4.
    Kindle4,
    /// Kindle Touch.
    Touch,
    /// `PaperWhite` 1.
    PaperWhite,
    /// `PaperWhite` 2.
    PaperWhite2,
    /// Basic 1.
    Basic,
    /// Voyage.
    Voyage,
    /// `PaperWhite` 3.
    PaperWhite3,
    /// Oasis 1.
    Oasis,
    /// Basic 2.
    Basic2,
    /// Oasis 2.
    Oasis2,
    /// `PaperWhite` 4.
    PaperWhite4,
    /// Basic 3.
    Basic3,
    /// Oasis 3.
    Oasis3,
    /// `PaperWhite` 5.
    PaperWhite5,
    /// Basic 4.
    Basic4,
    /// Scribe 1.
    Scribe,
    /// Basic 5.
    Basic5,
    /// `PaperWhite` 6.
    PaperWhite6,
    /// Scribe 2.
    Scribe2,
    /// `ColorSoft`.
    ColorSoft,
    /// Scribe 3.
    Scribe3,
    /// Scribe `ColorSoft`.
    ScribeColorSoft,
}

/// One entry in the canonical device catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceRecord {
    /// Numeric header code.
    pub code: DeviceCode,
    /// Stable source symbol inherited from `KindleTool`.
    pub symbol: &'static str,
    /// Serial-number representation.
    pub serial: &'static str,
    /// Human-readable product name.
    pub name: &'static str,
    /// Product family.
    pub family: DeviceFamily,
    /// Compatibility order within the product-family alias.
    pub family_order: u16,
    /// Whether the identifier is data-mined or not yet fully identified.
    pub unknown: bool,
    /// Whether the legacy CLI exposes it only with `KT_WITH_UNKNOWN_DEVCODES`.
    pub requires_unknown_flag: bool,
}

include!("devices_generated.rs");

#[derive(Clone, Copy, Debug)]
enum DeviceAliasKind {
    Symbol(&'static str),
    Symbols(&'static [&'static str]),
    Families(&'static [DeviceFamily]),
    None,
    UnknownSymbols,
    Auto,
}

#[derive(Clone, Copy, Debug)]
struct DeviceAliasRecord {
    name: &'static str,
    description: &'static str,
    kind: DeviceAliasKind,
}

use DeviceFamily::{
    Basic, Basic2, Basic3, Basic4, Basic5, ColorSoft, Kindle4, Oasis, Oasis2, Oasis3, PaperWhite,
    PaperWhite2, PaperWhite3, PaperWhite4, PaperWhite5, PaperWhite6, Scribe, Scribe2, Scribe3,
    ScribeColorSoft, Touch, Voyage,
};

const KINDLE2_SYMBOLS: &[&str] = &["Kindle2US", "Kindle2International"];
const KINDLE_DX_SYMBOLS: &[&str] = &["KindleDXUS", "KindleDXInternational", "KindleDXGraphite"];
const KINDLE3_SYMBOLS: &[&str] = &["Kindle3WiFi", "Kindle3WiFi3G", "Kindle3WiFi3GEurope"];
const LEGACY_SYMBOLS: &[&str] = &[
    "Kindle2US",
    "Kindle2International",
    "KindleDXUS",
    "KindleDXInternational",
    "KindleDXGraphite",
    "Kindle3WiFi",
    "Kindle3WiFi3G",
    "Kindle3WiFi3GEurope",
];
const KINDLE5_FAMILIES: &[DeviceFamily] = &[
    Touch,
    PaperWhite,
    PaperWhite2,
    Basic,
    Voyage,
    PaperWhite3,
    Oasis,
    Basic2,
    Oasis2,
    PaperWhite4,
    Basic3,
    Oasis3,
    PaperWhite5,
    Basic4,
    Scribe,
    Basic5,
    PaperWhite6,
    Scribe2,
    ColorSoft,
    Scribe3,
    ScribeColorSoft,
];

static DEVICE_ALIASES: &[DeviceAliasRecord] = &[
    DeviceAliasRecord {
        name: "k1",
        description: "Kindle 1",
        kind: DeviceAliasKind::Symbol("Kindle1"),
    },
    DeviceAliasRecord {
        name: "k2",
        description: "Kindle 2 US",
        kind: DeviceAliasKind::Symbol("Kindle2US"),
    },
    DeviceAliasRecord {
        name: "k2i",
        description: "Kindle 2 International",
        kind: DeviceAliasKind::Symbol("Kindle2International"),
    },
    DeviceAliasRecord {
        name: "dx",
        description: "Kindle DX US",
        kind: DeviceAliasKind::Symbol("KindleDXUS"),
    },
    DeviceAliasRecord {
        name: "dxi",
        description: "Kindle DX International",
        kind: DeviceAliasKind::Symbol("KindleDXInternational"),
    },
    DeviceAliasRecord {
        name: "dxg",
        description: "Kindle DX Graphite",
        kind: DeviceAliasKind::Symbol("KindleDXGraphite"),
    },
    DeviceAliasRecord {
        name: "k3w",
        description: "Kindle 3 WiFi",
        kind: DeviceAliasKind::Symbol("Kindle3WiFi"),
    },
    DeviceAliasRecord {
        name: "k3g",
        description: "Kindle 3 WiFi+3G",
        kind: DeviceAliasKind::Symbol("Kindle3WiFi3G"),
    },
    DeviceAliasRecord {
        name: "k3gb",
        description: "Kindle 3 WiFi+3G Europe",
        kind: DeviceAliasKind::Symbol("Kindle3WiFi3GEurope"),
    },
    DeviceAliasRecord {
        name: "k4",
        description: "Silver Kindle 4",
        kind: DeviceAliasKind::Symbol("Kindle4NonTouch"),
    },
    DeviceAliasRecord {
        name: "k4b",
        description: "Black Kindle 4",
        kind: DeviceAliasKind::Symbol("Kindle4NonTouchBlack"),
    },
    DeviceAliasRecord {
        name: "k5w",
        description: "Kindle Touch WiFi",
        kind: DeviceAliasKind::Symbol("Kindle5TouchWiFi"),
    },
    DeviceAliasRecord {
        name: "kindle2",
        description: "all Kindle 2 variants",
        kind: DeviceAliasKind::Symbols(KINDLE2_SYMBOLS),
    },
    DeviceAliasRecord {
        name: "kindledx",
        description: "all Kindle DX variants",
        kind: DeviceAliasKind::Symbols(KINDLE_DX_SYMBOLS),
    },
    DeviceAliasRecord {
        name: "kindle3",
        description: "all Kindle 3 variants",
        kind: DeviceAliasKind::Symbols(KINDLE3_SYMBOLS),
    },
    DeviceAliasRecord {
        name: "legacy",
        description: "Kindle 2, DX, and Kindle 3",
        kind: DeviceAliasKind::Symbols(LEGACY_SYMBOLS),
    },
    DeviceAliasRecord {
        name: "kindle4",
        description: "all Kindle 4 variants",
        kind: DeviceAliasKind::Families(&[Kindle4]),
    },
    DeviceAliasRecord {
        name: "touch",
        description: "all Kindle Touch variants",
        kind: DeviceAliasKind::Families(&[Touch]),
    },
    DeviceAliasRecord {
        name: "paperwhite",
        description: "all PaperWhite 1 variants",
        kind: DeviceAliasKind::Families(&[PaperWhite]),
    },
    DeviceAliasRecord {
        name: "paperwhite2",
        description: "all PaperWhite 2 variants",
        kind: DeviceAliasKind::Families(&[PaperWhite2]),
    },
    DeviceAliasRecord {
        name: "basic",
        description: "all Kindle Basic 1 variants",
        kind: DeviceAliasKind::Families(&[Basic]),
    },
    DeviceAliasRecord {
        name: "voyage",
        description: "all Kindle Voyage variants",
        kind: DeviceAliasKind::Families(&[Voyage]),
    },
    DeviceAliasRecord {
        name: "paperwhite3",
        description: "all PaperWhite 3 variants",
        kind: DeviceAliasKind::Families(&[PaperWhite3]),
    },
    DeviceAliasRecord {
        name: "oasis",
        description: "all Kindle Oasis 1 variants",
        kind: DeviceAliasKind::Families(&[Oasis]),
    },
    DeviceAliasRecord {
        name: "basic2",
        description: "all Kindle Basic 2 variants",
        kind: DeviceAliasKind::Families(&[Basic2]),
    },
    DeviceAliasRecord {
        name: "oasis2",
        description: "all Kindle Oasis 2 variants",
        kind: DeviceAliasKind::Families(&[Oasis2]),
    },
    DeviceAliasRecord {
        name: "paperwhite4",
        description: "all PaperWhite 4 variants",
        kind: DeviceAliasKind::Families(&[PaperWhite4]),
    },
    DeviceAliasRecord {
        name: "basic3",
        description: "all Kindle Basic 3 variants",
        kind: DeviceAliasKind::Families(&[Basic3]),
    },
    DeviceAliasRecord {
        name: "oasis3",
        description: "all Kindle Oasis 3 variants",
        kind: DeviceAliasKind::Families(&[Oasis3]),
    },
    DeviceAliasRecord {
        name: "paperwhite5",
        description: "all PaperWhite 5 variants",
        kind: DeviceAliasKind::Families(&[PaperWhite5]),
    },
    DeviceAliasRecord {
        name: "basic4",
        description: "all Kindle Basic 4 variants",
        kind: DeviceAliasKind::Families(&[Basic4]),
    },
    DeviceAliasRecord {
        name: "scribe",
        description: "all Kindle Scribe variants",
        kind: DeviceAliasKind::Families(&[Scribe]),
    },
    DeviceAliasRecord {
        name: "basic5",
        description: "all Kindle Basic 5 variants",
        kind: DeviceAliasKind::Families(&[Basic5]),
    },
    DeviceAliasRecord {
        name: "paperwhite6",
        description: "all PaperWhite 6 variants",
        kind: DeviceAliasKind::Families(&[PaperWhite6]),
    },
    DeviceAliasRecord {
        name: "scribe2",
        description: "all Kindle Scribe 2 variants",
        kind: DeviceAliasKind::Families(&[Scribe2]),
    },
    DeviceAliasRecord {
        name: "colorsoft",
        description: "all Kindle ColorSoft variants",
        kind: DeviceAliasKind::Families(&[ColorSoft]),
    },
    DeviceAliasRecord {
        name: "scribe3",
        description: "all Kindle Scribe 3 variants",
        kind: DeviceAliasKind::Families(&[Scribe3]),
    },
    DeviceAliasRecord {
        name: "scribecolorsoft",
        description: "all Kindle Scribe ColorSoft variants",
        kind: DeviceAliasKind::Families(&[ScribeColorSoft]),
    },
    DeviceAliasRecord {
        name: "kindle5",
        description: "all known Kindle 5 and newer variants",
        kind: DeviceAliasKind::Families(KINDLE5_FAMILIES),
    },
    DeviceAliasRecord {
        name: "none",
        description: "no device restriction (supported package types only)",
        kind: DeviceAliasKind::None,
    },
    DeviceAliasRecord {
        name: "auto",
        description: "current Kindle, read from /proc/usid or /proc/serial",
        kind: DeviceAliasKind::Auto,
    },
    DeviceAliasRecord {
        name: "unknown",
        description: "data-mined unknown codes; requires KT_WITH_UNKNOWN_DEVCODES",
        kind: DeviceAliasKind::UnknownSymbols,
    },
    DeviceAliasRecord {
        name: "datamined",
        description: "alias for unknown; requires KT_WITH_UNKNOWN_DEVCODES",
        kind: DeviceAliasKind::UnknownSymbols,
    },
];

/// Read-only access to the canonical Kindle device catalog.
pub struct DeviceCatalog;

impl DeviceCatalog {
    /// All known records in compatibility order.
    #[must_use]
    pub const fn all() -> &'static [DeviceRecord] {
        DEVICE_CATALOG
    }

    /// Find a device by numeric code.
    #[must_use]
    pub fn by_code(code: DeviceCode) -> Option<&'static DeviceRecord> {
        DEVICE_CATALOG.iter().find(|record| record.code == code)
    }

    /// Find a device by its serial-number code.
    #[must_use]
    pub fn by_serial(serial: &str) -> Option<&'static DeviceRecord> {
        DEVICE_CATALOG
            .iter()
            .find(|record| record.serial.eq_ignore_ascii_case(serial))
    }

    /// Documented CLI aliases and their descriptions, in help-display order.
    #[must_use]
    pub fn aliases() -> impl ExactSizeIterator<Item = (&'static str, &'static str)> {
        DEVICE_ALIASES
            .iter()
            .map(|alias| (alias.name, alias.description))
    }

    /// Expand a documented `KindleTool` device alias.
    pub fn expand_alias(alias: &str, include_unknown: bool) -> Result<Vec<DeviceCode>> {
        let normalized = alias.to_ascii_lowercase();
        let alias = DEVICE_ALIASES
            .iter()
            .find(|record| record.name == normalized)
            .ok_or_else(|| Error::InvalidField {
                field: "device",
                message: format!("unknown device alias {alias}"),
            })?;
        match alias.kind {
            DeviceAliasKind::Symbol(symbol) => Ok(vec![code_for_symbol(symbol)?]),
            DeviceAliasKind::Symbols(symbols) => symbols
                .iter()
                .map(|symbol| code_for_symbol(symbol))
                .collect(),
            DeviceAliasKind::Families(families) => {
                let mut records = DEVICE_CATALOG
                    .iter()
                    .filter(|record| families.contains(&record.family))
                    .filter(|record| record.family_order != u16::MAX)
                    .filter(|record| include_unknown || !record.requires_unknown_flag)
                    .collect::<Vec<_>>();
                records.sort_by_key(|record| {
                    (
                        families
                            .iter()
                            .position(|family| *family == record.family)
                            .unwrap_or(usize::MAX),
                        record.family_order,
                    )
                });
                Ok(records.into_iter().map(|record| record.code).collect())
            }
            DeviceAliasKind::None => Ok(Vec::new()),
            DeviceAliasKind::UnknownSymbols if include_unknown => Ok(DEVICE_CATALOG
                .iter()
                .filter(|record| record.symbol.starts_with("ValidKindleUnknown"))
                .map(|record| record.code)
                .collect()),
            DeviceAliasKind::UnknownSymbols => Err(Error::InvalidField {
                field: "device",
                message: format!(
                    "device alias {} requires KT_WITH_UNKNOWN_DEVCODES",
                    alias.name
                ),
            }),
            DeviceAliasKind::Auto => Err(Error::InvalidField {
                field: "device",
                message: "auto must be resolved on a Kindle host".to_owned(),
            }),
        }
    }
}

fn code_for_symbol(symbol: &str) -> Result<DeviceCode> {
    DEVICE_CATALOG
        .iter()
        .find(|record| record.symbol == symbol)
        .map(|record| record.code)
        .ok_or_else(|| Error::InvalidField {
            field: "device catalog",
            message: format!("alias references missing device symbol {symbol}"),
        })
}

/// Decode Kindle's modified Crockford-style base32 alphabet.
pub fn decode_base32(value: &str) -> Result<u32> {
    value.bytes().try_fold(0_u32, |result, byte| {
        let upper = byte.to_ascii_uppercase();
        let digit = u32::try_from(
            BASE32
                .iter()
                .position(|candidate| *candidate == upper)
                .ok_or_else(|| Error::InvalidField {
                    field: "base32",
                    message: format!("character {:?} is out of range", char::from(byte)),
                })?,
        )
        .expect("base32 alphabet length fits in u32");
        result
            .checked_mul(32)
            .and_then(|number| number.checked_add(digit))
            .ok_or_else(|| Error::InvalidField {
                field: "base32",
                message: "value overflows u32".to_owned(),
            })
    })
}

/// Encode Kindle's modified Crockford-style base32 alphabet.
#[must_use]
pub fn encode_base32(mut value: u32, minimum_width: usize) -> String {
    let mut output = Vec::new();
    loop {
        output.push(BASE32[(value % 32) as usize]);
        value /= 32;
        if value == 0 {
            break;
        }
    }
    while output.len() < minimum_width {
        output.push(b'0');
    }
    output.reverse();
    String::from_utf8(output).expect("base32 alphabet is ASCII")
}

#[cfg(test)]
mod tests {
    use super::{DeviceCatalog, DeviceCode, decode_base32, encode_base32};

    #[test]
    fn base32_matches_known_pw3_code() {
        assert_eq!(decode_base32("0G1").unwrap(), 0x201);
        assert_eq!(encode_base32(0x201, 3), "0G1");
    }

    #[test]
    fn kt6_alias_is_gated() {
        assert!(
            DeviceCatalog::expand_alias("basic5", false)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            DeviceCatalog::expand_alias("basic5", true).unwrap().len(),
            7
        );
    }

    #[test]
    fn numeric_lookup_round_trips() {
        let record = DeviceCatalog::by_code(DeviceCode(0x201)).unwrap();
        assert_eq!(record.serial, "0G1");
    }

    #[test]
    fn catalog_serial_codes_are_unique_and_round_trip() {
        let mut codes = std::collections::HashSet::new();
        let mut serials = std::collections::HashSet::new();
        for record in DeviceCatalog::all() {
            assert!(codes.insert(record.code));
            assert!(serials.insert(record.serial.to_ascii_uppercase()));
            assert_eq!(DeviceCatalog::by_serial(record.serial), Some(record));
            assert_eq!(record.code.serial_code(), record.serial);
        }
    }

    #[test]
    fn catalog_aliases_are_unique_and_resolve() {
        let mut aliases = std::collections::HashSet::new();
        for (alias, _) in DeviceCatalog::aliases() {
            assert!(aliases.insert(alias), "duplicate alias {alias}");
            match alias {
                "none" => assert!(DeviceCatalog::expand_alias(alias, true).unwrap().is_empty()),
                "auto" => assert!(DeviceCatalog::expand_alias(alias, true).is_err()),
                _ => assert!(
                    !DeviceCatalog::expand_alias(alias, true).unwrap().is_empty(),
                    "alias {alias} is empty"
                ),
            }
        }
    }
}
