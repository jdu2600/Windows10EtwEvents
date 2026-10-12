# Unknown providers

These providers are registered with Windows, but no event schema could be read for them:

* TDH (`tdh.dll`) will not parse their events. The `manifest/` data is read straight from TDH: [`TdhGetAllEventsInformation`](https://learn.microsoft.com/windows/win32/etw/tdhgetalleventsinformation), asked about every event version, returns nothing for these providers.
* There is no MOF class for them in the WMI repository, which is where the `mof/` data comes from.

Where the Event Log API (`wevtapi.dll`) can still read the provider's `WEVT_TEMPLATE` resource, the events are reconstructed from that on a best-effort basis. Those rows stay here rather than in `manifest/`. They don't count towards the event totals or appear in the event browser.

Captures made with TraceEvent 2.0.48 also list `Volsnap` and `Microsoft-Windows-CertificateServicesClient-CertEnroll` here. TDH reads both, but TraceEvent stopped scanning event versions at the first gap, and these providers' events sit at version 6 and 90 (see [Event Log message ids](#event-log-message-ids)). They are in `manifest/` now.

## File format

Each file has one of two layouts.

**Nothing recovered:** just the provider and why TDH failed.

```
provider	tdh_status
Microsoft-Windows-USB-CCID	ERROR_FILE_NOT_FOUND
```

**Events recovered:** the same columns as `manifest/`, plus `tdh_status` on every row.

```
provider	event_id	version	event(fields)	opcode	keywords	task	level	evtlog_channel	evtlog_message	tdh_status
Microsoft-Windows-WinML	3	0	NameStart3(Pointer pNet, UInt32 WinMLNetNameSize, AnsiString WinMLNetName)	Start	Perf	Name	Always	Microsoft-Windows-WinML/Analytic		ERROR_MUI_FILE_NOT_FOUND
```

Captures from before `tdh_status` was added list only the provider name.

Reconstructed rows are named by the same rules as `manifest/`: task + opcode where the manifest names the task (`NameStart3`), otherwise `Event_<id>[_<opcode>][_<severity>][_V<version>]` (`Event_2`). They differ from the `manifest/` rows in these ways:

* **The names going into those rules are the manifest's symbolic names.** TDH names tasks and opcodes with their localized display strings, but those strings are usually what is missing here. So WinML's task is `Name` (its real `name=` attribute) and its opcodes are `win:Start`/`win:Stop`.
* **`evtlog_message` is filled in only when the message string still resolves.** For the MUI-missing providers it's usually empty.

### Event Log message ids

Event Log-era events (keyword `win:EventlogClassic`) keep a 32-bit message id, `Severity|C|R|Facility|Code` (e.g. Volsnap's `0xC0060001`). The manifest compiler packs it into the ETW event descriptor: the code becomes the id, the low byte of the facility the version, and the top byte (severity, C, R and the facility's high bits) the opcode. The full id is stored alongside.

Both folders publish these events as the Event Log records them: the code as `event_id`, version 0, no opcode, and the severity in the name. `0xC0060001` is `Event_1_Error`, not version 6 with opcode 192. Two events that share a code, like MSDTC's `0x8000D01A` and `0xC000D01A`, become `Event_53274_Warning` and `Event_53274_Error`.

## tdh_status

This is the result of [`TdhEnumerateManifestProviderEvents`](https://learn.microsoft.com/windows/win32/api/tdh/nf-tdh-tdhenumeratemanifestproviderevents) for the provider's GUID, called with no buffer: TDH's own account of why it has no events.

| tdh_status | What is actually wrong | Events recovered? |
|---|---|---|
| `ERROR_MUI_FILE_NOT_FOUND` | The resource file is language-neutral, but its `.mui` satellite was never shipped. | Yes |
| `ERROR_EMPTY` | The manifest declares no events. | Nothing to recover |
| `ERROR_RESOURCE_TYPE_NOT_FOUND` | The resource file has no `WEVT_TEMPLATE` resource. | No |
| `ERROR_FILE_NOT_FOUND` | The resource file doesn't exist. | No |
| `ERROR_INVALID_DATA` | The resource file's manifest doesn't contain this provider. | No |

The examples below were observed on Windows 11 build 26200.

### ERROR_MUI_FILE_NOT_FOUND

The resource file has a `WEVT_TEMPLATE` and an `MUI` resource. The `MUI` resource marks the file as language-neutral and says its strings live in a satellite `<file>.mui`. That satellite was never shipped, in any language.

TDH resolves a provider's strings (task, opcode, level and keyword names) together with its schema. It also sends even an explicitly loaded binary through the MUI loader. When the satellite is missing, every TDH call for the provider fails:

* enumeration returns `ERROR_MUI_FILE_NOT_FOUND`;
* per-event lookups (`TdhGetManifestEventInformation`, `TdhGetEventInformation`) return `ERROR_NOT_FOUND`, for every event id. Brute-forcing ids doesn't help;
* `TdhGetAllEventsInformation` returns `ERROR_MUI_FILE_NOT_FOUND` for version 0 and `ERROR_NOT_FOUND` for every other version.

There is no partial result. Stripping the `MUI` resource from a copy of the binary only changes the error. The copy has no message table, so it fails with `ERROR_RESOURCE_TYPE_NOT_FOUND`. Adding an empty message table then fails with `ERROR_MR_MID_NOT_FOUND` on the first missing string.

Example: `Microsoft-Windows-WinML` is registered to `%SystemRoot%\system32\WinML.dll`, a 64 KB DLL with `WEVT_TEMPLATE` and `MUI` resources, no string or message table, and no `winml.dll.mui`.

**Events can be recovered.** The Event Log API reads the same template but only formats a string when asked for one. So the events, their templates and the symbolic names all survive. Only the localized text is lost.

To decode these events with TDH in your own consumer, you have to fake the schema. Rebuild a manifest XML from the Event Log metadata and load it with `TdhLoadManifest`. A loaded XML manifest takes precedence over the broken registration. A binary loaded with `TdhLoadManifestFromBinary` does not.

### ERROR_EMPTY

TDH says the provider's manifest defines no events, and on Windows 11 26200 that's true for every provider here. Its `WEVT_TEMPLATE` has channels, keywords, levels and so on, but no `EVNT` element. For example, `ddisplay.dll` contains `CHAN PRVA OPCO LEVL TASK KEYW` only. These are registered for their channels or keywords, or the events are logged by a different provider. There is nothing to recover.

`Microsoft-Windows-CertificateServicesClient-CertEnroll` also gets `ERROR_EMPTY`, although it declares 80 events. `TdhGetAllEventsInformation` returns them, so it is in `manifest/`; why the enumeration disagrees is unknown.

### ERROR_RESOURCE_TYPE_NOT_FOUND

The registered resource file was found but has no `WEVT_TEMPLATE` resource. It may be a stub, or the template was never compiled into it. For example, `MFDshowReverseBridge.dll`, `drivers\bfs.sys` and `drivers\wdnisdrv.sys` have no template. Neither TDH nor the Event Log API has anything to read.

### ERROR_FILE_NOT_FOUND

The registered resource file doesn't exist. Either the component isn't installed (e.g. `Microsoft-Windows-USB-CCID` → `drivers\UMDF\UsbccidDriver.dll`), or the registered path can't be resolved. For example, `Microsoft-Windows-SystemSettingsThreshold` is registered with a literal `$(runtime.windows)\ImmersiveControlPanel\SystemSettings.exe`.

### ERROR_INVALID_DATA

The resource file exists and has a `WEVT_TEMPLATE`, but that template doesn't contain this provider's GUID. The registration points at the wrong binary. For example:

* `Microsoft-Windows-DxgKrnl-SysMm` (`{9de90b19-…}`) is registered to `drivers\dxgkrnl.sys`, whose manifest only contains `{802ec45a-…}`.
* `Microsoft-Windows-Privacy-Auditing-DiagnosticData` and `-TailoredExperiences` are registered to `diagtrack.dll`, whose manifest only contains `{6489b27f-…}` and `{030f2f57-…}`.

The Event Log API fails the same way, so nothing can be recovered from the registered file.
