# Unknown providers

These providers are registered with Windows, but no event schema could be read for them:

* TDH (`tdh.dll`) will not parse their events. The `manifest/` data is read straight from TDH: [`TdhGetAllEventsInformation`](https://learn.microsoft.com/windows/win32/etw/tdhgetalleventsinformation), asked about every event version, returns nothing for these providers.
* The Event Log API (`wevtapi.dll`) can't read their manifest either. Where it can, the provider's events are in `manifest/` (see [Providers TDH can't decode](#providers-tdh-cant-decode)).
* There is no MOF class for them in the WMI repository, which is where the `mof/` data comes from.

Captures made with TraceEvent 2.0.48 also list providers here that TDH can read, such as `Volsnap` and `Microsoft-Windows-CertificateServicesClient-CertEnroll`. TraceEvent stopped scanning event versions at the first gap, and these providers' events sit at version 6 and 90 (see [Event Log message ids](#event-log-message-ids)).

## File format

```
provider	tdh_status	resource_file
Microsoft-Windows-SystemSettingsThreshold	ERROR_FILE_NOT_FOUND	$(runtime.windows)\ImmersiveControlPanel\SystemSettings.exe
```

* `tdh_status` is why TDH has no events for the provider (see [tdh_status](#tdh_status)).
* `resource_file` is the manifest file the provider is registered with: its `ResourceFileName` under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers`, exactly as registered, with environment variables unexpanded. It's empty if the provider isn't registered there.

Older captures list only the provider name.

## tdh_status

This is the result of [`TdhEnumerateManifestProviderEvents`](https://learn.microsoft.com/windows/win32/api/tdh/nf-tdh-tdhenumeratemanifestproviderevents) for the provider's GUID, called with no buffer: TDH's own account of why it has no events.

| tdh_status | What is actually wrong |
|---|---|
| `ERROR_EMPTY` | The manifest declares no events. |
| `ERROR_FILE_NOT_FOUND` | The registered resource file doesn't exist or can't be resolved. |
| `ERROR_RESOURCE_TYPE_NOT_FOUND` | The resource file has no `WEVT_TEMPLATE` resource. |
| `ERROR_INVALID_DATA` | The resource file's manifest doesn't contain this provider. |

The examples below were observed on Windows 11 build 26200.

### ERROR_EMPTY

TDH says the provider's manifest defines no events, and on Windows 11 26200 that's true for every provider here. Its `WEVT_TEMPLATE` has channels, keywords, levels and so on, but no `EVNT` element. For example, `ddisplay.dll` contains `CHAN PRVA OPCO LEVL TASK KEYW` only. These are registered for their channels or keywords, or the events are logged by a different provider. There is nothing to recover.

`TdhEnumerateManifestProviderEvents` can also return `ERROR_EMPTY` for a manifest that does have events. It walks event versions upward from 0 and gives up after 11 empty versions in a row, so `Microsoft-Windows-CertificateServicesClient-CertEnroll`, whose 80 events are all at version 90 (the low byte of facility `0x25A`), looks empty to it. `TdhGetAllEventsInformation`, asked about every version, returns them, so CertEnroll is in `manifest/`.

### ERROR_FILE_NOT_FOUND

The registered resource file doesn't exist or can't be resolved. The component is usually installed, though, and its manifest is in another file; it's the registration that is broken. For example:

* `Microsoft-Windows-SystemSettingsThreshold` is registered with a literal `$(runtime.windows)\ImmersiveControlPanel\SystemSettings.exe`. The manifest is in `C:\Windows\ImmersiveControlPanel\SystemSettings.exe`.
* `Microsoft-Windows-USB-CCID` is registered to `drivers\UMDF\UsbccidDriver.dll`, which only exists in the DriverStore. The same manifest is also in `drivers\UMDF\SMCCx.dll`.
* `Microsoft-Windows-WDAG-PolicyEvaluator-GP` is registered to `hvsigpext.dll`, which doesn't exist. Its manifest is in `hvsievaluator.exe`.
* Third-party drivers have registrations in the wrong folder or for a package version that is no longer installed.

Neither TDH nor the Event Log API looks past the registration. Even loading the right file with `TdhLoadManifestFromBinary` doesn't help, because the broken registration takes precedence.

### ERROR_RESOURCE_TYPE_NOT_FOUND

The registered resource file was found but has no `WEVT_TEMPLATE` resource. It may be a stub, or the template was never compiled into it. For example, `MFDshowReverseBridge.dll`, `drivers\bfs.sys` and `drivers\wdnisdrv.sys` have no template. Neither TDH nor the Event Log API has anything to read.

### ERROR_INVALID_DATA

The resource file exists and has a `WEVT_TEMPLATE`, but that template doesn't contain this provider's GUID. The registration points at the wrong binary. For example:

* `Microsoft-Windows-DxgKrnl-SysMm` (`{9de90b19-…}`) is registered to `drivers\dxgkrnl.sys`, whose manifest only contains `{802ec45a-…}`.
* `Microsoft-Windows-Privacy-Auditing-DiagnosticData` and `-TailoredExperiences` are registered to `diagtrack.dll`, whose manifest only contains `{6489b27f-…}` and `{030f2f57-…}`.

The Event Log API fails the same way, so nothing can be recovered from the registered file.

## Providers TDH can't decode

Some providers' manifests are fine, yet TDH still fails on them with `ERROR_MUI_FILE_NOT_FOUND`. These used to be listed here; their events are in `manifest/` now, read with the Event Log API. On Windows 11 26200 they are:

* `Microsoft-System-Diagnostics-DiagnosticInvoker`
* `Microsoft-Windows-Configuration-Change-Monitor`
* `Microsoft-Windows-Devices-Query`
* `Microsoft-Windows-GraphicsCapture-API`
* `Microsoft-Windows-I3C-HIDI3C`
* `Microsoft-Windows-WinML`
* `Microsoft-Windows-WorkFolders`

The resource file has a `WEVT_TEMPLATE` and an `MUI` resource. The `MUI` resource marks the file as language-neutral and says its strings live in a satellite `<file>.mui`. That satellite was never shipped, in any language. For example, `Microsoft-Windows-WinML` is registered to `%SystemRoot%\system32\WinML.dll`, a 64 KB DLL with `WEVT_TEMPLATE` and `MUI` resources, no string or message table, and no `winml.dll.mui`.

TDH resolves a provider's strings (task, opcode, level and keyword names) together with its schema, and it sends even an explicitly loaded binary through the MUI loader. When the satellite is missing, every TDH call for the provider fails:

* enumeration returns `ERROR_MUI_FILE_NOT_FOUND`;
* per-event lookups (`TdhGetManifestEventInformation`, `TdhGetEventInformation`) return `ERROR_NOT_FOUND`, for every event id. Brute-forcing ids doesn't help;
* `TdhGetAllEventsInformation` returns `ERROR_MUI_FILE_NOT_FOUND` for version 0 and `ERROR_NOT_FOUND` for every other version.

Stripping the `MUI` resource from a copy of the binary only changes the error. The copy has no message table, so it fails with `ERROR_RESOURCE_TYPE_NOT_FOUND`. Adding an empty message table then fails with `ERROR_MR_MID_NOT_FOUND` on the first missing string.

The Event Log API reads the same template but only formats a string when asked for one. So the events, their templates and the symbolic names all survive, and only the localized text is lost. In `manifest/` these providers differ from the others in two ways:

* **Task and opcode names are the manifest's symbolic names** (WinML's task `Name`, opcodes `win:Start`/`win:Stop`), because the localized display names TDH would use are what's missing.
* **`evtlog_message` is `<ERROR_MUI_FILE_NOT_LOADED>`** for an event whose message can't be loaded. It's empty when the event declares no message, as WinML's events don't.

To decode these events with TDH in your own consumer, you have to fake the schema. Rebuild a manifest XML from the Event Log metadata and load it with `TdhLoadManifest`. A loaded XML manifest takes precedence over the broken registration. A binary loaded with `TdhLoadManifestFromBinary` does not.

## Event Log message ids

This applies to `manifest/`. Event Log-era events (keyword `win:EventlogClassic`) keep a 32-bit message id, `Severity|C|R|Facility|Code` (e.g. Volsnap's `0xC0060001`). The manifest compiler packs it into the ETW event descriptor: the code becomes the id, the low byte of the facility the version, and the top byte (severity, C, R and the facility's high bits) the opcode. The full id is stored alongside.

`manifest/` publishes these events as the Event Log records them: the code as `event_id`, version 0 and no opcode. Where the manifest names no task, they are named by the whole message id, as in [PerfView #2483](https://github.com/microsoft/perfview/pull/2483). `0xC0060001` is `Message_0xC0060001`, not version 6 with opcode 192. Two events that share a code, like MSDTC's `0x8000D01A` and `0xC000D01A`, are `Message_0x8000D01A` and `Message_0xC000D01A`.
