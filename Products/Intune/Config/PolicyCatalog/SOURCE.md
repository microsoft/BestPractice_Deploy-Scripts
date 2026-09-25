# Intune policy catalog source record

The 19 JSON payloads in this directory were normalized from an existing Intune
implementation for use as candidate configuration data.

The source archive linked its mobile policies to Microsoft's Intune protection
and configuration levels, and linked its Windows policies to the
[Intune ACSC Windows Hardening Guidelines](https://github.com/microsoft/Intune-ACSC-Windows-Hardening-Guidelines).

Normalization made these repository-safe changes:

- Removed root-level exported object IDs, creation timestamps, modification
  timestamps, creation source, priority metadata, setting counts, and version
  fields.
- Added the Settings Catalog `@odata.context` discriminator to the iOS
  Personal baseline, Windows Edge hardening, and Windows security baseline
  payloads. The source script skipped those three files because it could not
  map them to a write command.
- Corrected the iOS Personal Settings Catalog root property from `displayName`
  to the required `name`.
- Removed a placeholder Factory Reset Protection account from the Android
  Fully Managed Advanced payload.
- Renamed files to stable lowercase names without spaces.
- Preserved nested setting-definition IDs and template references required to
  describe Settings Catalog content.
- Recorded the original and normalized SHA-256 digest for each payload in
  `catalog.psd1`. Normalized digests use canonical LF line endings so the same
  reviewed content verifies on Windows, macOS, and Linux.

The source archive did not contain Android or iOS app protection payloads. It
contained app protection command mappings only, so this catalog does not supply
the payloads required for a future app protection write.

All entries remain `ApplyStatus = 'Blocked'`. Importing this catalog does not
authorize Microsoft Graph writes, assignment, tenant-wide targeting, adoption,
replacement, or deletion.
