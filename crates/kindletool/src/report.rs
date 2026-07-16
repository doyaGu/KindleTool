use crate::devices::{DeviceCatalog, DeviceCode};
use crate::model::{BundleMagic, PackageDescriptor, PackageHeader};
use std::fmt::Write;

/// Render package information in `KindleTool`'s traditional human-readable form.
#[must_use]
pub fn render_package_info(info: &PackageDescriptor, include_codes: bool) -> String {
    let mut output = String::new();
    if let Some(envelope) = &info.envelope {
        bundle_line(&mut output, BundleMagic::Sp01);
        let _ = writeln!(output, "Cert number    {}", envelope.certificate.raw());
        let _ = writeln!(output, "Cert file      {}", envelope.certificate.label());
    }
    bundle_line(&mut output, info.header.magic());
    match &info.header {
        PackageHeader::OtaV1(header) => {
            let _ = writeln!(output, "Bundle Type    OTA V1");
            let _ = writeln!(output, "MD5 Hash       {}", header.md5);
            let _ = writeln!(output, "Minimum OTA    {}", header.source_revision);
            let _ = writeln!(output, "Target OTA     {}", header.target_revision);
            device_line(&mut output, header.device, include_codes);
            let _ = writeln!(output, "Optional       {}", header.optional);
        }
        PackageHeader::OtaV2(header) => {
            let _ = writeln!(output, "Bundle Type    OTA V2");
            let _ = writeln!(output, "Minimum OTA    {}", header.source_revision);
            let _ = writeln!(output, "Target OTA     {}", header.target_revision);
            let _ = writeln!(output, "Devices        {}", header.devices.len());
            for device in &header.devices {
                device_line(&mut output, *device, include_codes);
            }
            let _ = writeln!(output, "Critical       {}", header.critical);
            let _ = writeln!(
                output,
                "Padding Byte   {} (0x{:02X})",
                header.padding, header.padding
            );
            let _ = writeln!(output, "MD5 Hash       {}", header.md5);
            let _ = writeln!(output, "Metadata       {}", header.metadata.len());
            for metadata in &header.metadata {
                let _ = writeln!(
                    output,
                    "Metastring     {}",
                    String::from_utf8_lossy(metadata)
                );
            }
        }
        PackageHeader::RecoveryV1(header) => {
            let _ = writeln!(output, "Bundle Type    Recovery");
            let _ = writeln!(output, "MD5 Hash       {}", header.md5);
            let _ = writeln!(output, "Magic 1        {}", header.magic_1);
            let _ = writeln!(output, "Magic 2        {}", header.magic_2);
            let _ = writeln!(output, "Minor          {}", header.minor);
            if header.header_revision == 2 {
                let _ = writeln!(
                    output,
                    "Target OTA     {}",
                    header.target_revision.unwrap_or_default()
                );
                platform_line(
                    &mut output,
                    header.platform.unwrap_or(crate::model::Platform(0)),
                );
                let _ = writeln!(output, "Header Rev     {}", header.header_revision);
                board_line(&mut output, header.board.unwrap_or(crate::model::Board(0)));
            } else if let Some(device) = header.device {
                if let Ok(device) = u16::try_from(device) {
                    device_line(&mut output, DeviceCode(device), include_codes);
                } else {
                    let _ = writeln!(output, "Device         Unknown (0x{device:08X})");
                }
            }
        }
        PackageHeader::RecoveryV2(header) => {
            let _ = writeln!(output, "Bundle Type    Recovery V2");
            let _ = writeln!(output, "Target OTA     {}", header.target_revision);
            let _ = writeln!(output, "MD5 Hash       {}", header.md5);
            let _ = writeln!(output, "Magic 1        {}", header.magic_1);
            let _ = writeln!(output, "Magic 2        {}", header.magic_2);
            let _ = writeln!(output, "Minor          {}", header.minor);
            platform_line(&mut output, header.platform);
            let _ = writeln!(output, "Header Rev     {}", header.header_revision);
            board_line(&mut output, header.board);
            let _ = writeln!(output, "Devices        {}", header.devices.len());
            for device in &header.devices {
                device_line(&mut output, *device, include_codes);
            }
        }
        PackageHeader::Component(header) => {
            let _ = writeln!(output, "Bundle Type    Component");
            let _ = writeln!(output, "Min    OTA     {}", header.minimum_revision);
            let _ = writeln!(output, "Target OTA     {}", header.target_revision);
            let _ = writeln!(output, "SHA256 Hash    {}", header.sha256);
            let _ = writeln!(
                output,
                "Component      {} (0x{:02X})",
                header.component, header.component
            );
            platform_line(&mut output, header.platform);
            let _ = writeln!(output, "Header Rev     {}", header.header_revision);
            let _ = writeln!(output, "Devices        {}", header.devices.len());
            for device in &header.devices {
                device_line(&mut output, *device, include_codes);
            }
        }
        PackageHeader::Userdata { .. } => {}
        PackageHeader::Android => {
            let _ = writeln!(output, "Nothing to do!");
        }
    }
    output
}

/// Render the legacy shell-friendly metadata assignment stream.
#[must_use]
pub fn render_shell_metadata(info: &PackageDescriptor) -> String {
    let header = &info.header;
    let mut fields = vec![
        ("pkgBundleMagic", header.magic().to_string()),
        ("pkgBundleType", bundle_type(header).to_owned()),
    ];
    match header {
        PackageHeader::OtaV1(value) => {
            fields.extend([
                ("pkgMinOTA", value.source_revision.to_string()),
                ("pkgTargetOTA", value.target_revision.to_string()),
                ("pkgDeviceCodes", value.device.0.to_string()),
                ("pkgDeviceSNs", value.device.serial_code()),
                ("pkgMD5Hash", value.md5.to_string()),
                ("pkgOptional", value.optional.to_string()),
                (
                    "pkgPaddingByte",
                    info.raw_inner_header
                        .get(15)
                        .copied()
                        .unwrap_or_default()
                        .to_string(),
                ),
            ]);
        }
        PackageHeader::OtaV2(value) => {
            fields.extend([
                ("pkgMinOTA", value.source_revision.to_string()),
                ("pkgTargetOTA", value.target_revision.to_string()),
                ("pkgDevices", value.devices.len().to_string()),
                ("pkgDeviceCodes", device_codes(&value.devices)),
                ("pkgDeviceSNs", device_serials(&value.devices)),
                ("pkgCritical", value.critical.to_string()),
                ("pkgPaddingByte", value.padding.to_string()),
                ("pkgMD5Hash", value.md5.to_string()),
                ("pkgMetadataStrings", value.metadata.len().to_string()),
            ]);
        }
        PackageHeader::RecoveryV1(value) => {
            fields.extend([
                ("pkgMD5Hash", value.md5.to_string()),
                ("pkgMagic1", value.magic_1.to_string()),
                ("pkgMagic2", value.magic_2.to_string()),
                ("pkgMinor", value.minor.to_string()),
                ("pkgHeaderRev", value.header_revision.to_string()),
            ]);
            if value.header_revision == 2 {
                let platform = value.platform.unwrap_or(crate::model::Platform(0));
                let board = value.board.unwrap_or(crate::model::Board(0));
                fields.extend([
                    (
                        "pkgTargetOTA",
                        value.target_revision.unwrap_or_default().to_string(),
                    ),
                    ("pkgPlatform", platform.0.to_string()),
                    ("pkgPlatformName", platform.name().to_owned()),
                    ("pkgBoard", board.0.to_string()),
                    ("pkgBoardName", board.name().to_owned()),
                ]);
            } else if let Some(device) = value.device {
                fields.push(("pkgDeviceCodes", device.to_string()));
                if let Ok(code) = u16::try_from(device) {
                    fields.push(("pkgDeviceSNs", DeviceCode(code).serial_code()));
                }
            }
        }
        PackageHeader::RecoveryV2(value) => {
            fields.extend([
                ("pkgTargetOTA", value.target_revision.to_string()),
                ("pkgMD5Hash", value.md5.to_string()),
                ("pkgMagic1", value.magic_1.to_string()),
                ("pkgMagic2", value.magic_2.to_string()),
                ("pkgMinor", value.minor.to_string()),
                ("pkgPlatform", value.platform.0.to_string()),
                ("pkgPlatformName", value.platform.name().to_owned()),
                ("pkgHeaderRev", value.header_revision.to_string()),
                ("pkgBoard", value.board.0.to_string()),
                ("pkgBoardName", value.board.name().to_owned()),
                ("pkgDevices", value.devices.len().to_string()),
                ("pkgDeviceCodes", device_codes(&value.devices)),
                ("pkgDeviceSNs", device_serials(&value.devices)),
            ]);
        }
        PackageHeader::Component(value) => {
            fields.extend([
                ("pkgMinOTA", value.minimum_revision.to_string()),
                ("pkgTargetOTA", value.target_revision.to_string()),
                ("pkgSHA256Hash", value.sha256.to_string()),
                ("pkgComponent", value.component.to_string()),
                ("pkgPlatform", value.platform.0.to_string()),
                ("pkgPlatformName", value.platform.name().to_owned()),
                ("pkgHeaderRev", value.header_revision.to_string()),
                ("pkgDevices", value.devices.len().to_string()),
                ("pkgDeviceCodes", device_codes(&value.devices)),
                ("pkgDeviceSNs", device_serials(&value.devices)),
            ]);
        }
        PackageHeader::Userdata { .. } | PackageHeader::Android => {}
    }
    fields
        .into_iter()
        .fold(String::new(), |mut output, (name, value)| {
            let _ = write!(output, "{name}={};", shell_quote(&value));
            output
        })
}

fn bundle_line(output: &mut String, magic: BundleMagic) {
    let _ = writeln!(output, "Bundle         {magic} {}", magic.description());
}

fn device_line(output: &mut String, code: DeviceCode, include_codes: bool) {
    let record = DeviceCatalog::by_code(code);
    let name = record.map_or("Unknown", |value| value.name);
    if include_codes {
        let _ = writeln!(
            output,
            "Device         {name} ({} -> 0x{:02X})",
            code.serial_code(),
            code.0
        );
    } else if record.is_some() {
        let _ = writeln!(output, "Device         {name}");
    } else {
        let _ = writeln!(output, "Device         Unknown (0x{:02X})", code.0);
    }
}

fn platform_line(output: &mut String, platform: crate::model::Platform) {
    if platform.name() == "Unknown" {
        let _ = writeln!(output, "Platform       Unknown (0x{:02X})", platform.0);
    } else {
        let _ = writeln!(output, "Platform       {}", platform.name());
    }
}

fn board_line(output: &mut String, board: crate::model::Board) {
    if board.name() == "Unknown" {
        let _ = writeln!(output, "Board          Unknown (0x{:02X})", board.0);
    } else {
        let _ = writeln!(output, "Board          {}", board.name());
    }
}

fn bundle_type(header: &PackageHeader) -> &'static str {
    match header {
        PackageHeader::OtaV1(_) => "OTA V1",
        PackageHeader::OtaV2(_) => "OTA V2",
        PackageHeader::RecoveryV1(_) => "Recovery",
        PackageHeader::RecoveryV2(_) => "Recovery V2",
        PackageHeader::Component(_) => "Component",
        PackageHeader::Userdata { .. } => "Userdata",
        PackageHeader::Android => "Android",
    }
}

fn device_codes(devices: &[DeviceCode]) -> String {
    devices
        .iter()
        .map(|device| device.0.to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

fn device_serials(devices: &[DeviceCode]) -> String {
    devices
        .iter()
        .map(|device| device.serial_code())
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
