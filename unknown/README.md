# Unknown providers

These providers are registered with Windows, but no event schema could be read for them:

* TDH (`tdh.dll`) will not parse their events. [TraceEvent](https://www.nuget.org/packages/Microsoft.Diagnostics.Tracing.TraceEvent), which produces the `manifest/` data, decodes providers through TDH.
* There is no MOF class for them in the WMI repository, which is where the `mof/` data comes from.

Where the Event Log API (`wevtapi.dll`) can still read the provider's `WEVT_TEMPLATE` resource, the events are reconstructed from that on a best-effort basis. Those rows stay here rather than in `manifest/`. They don't count towards the event totals or appear in the event browser.

## File format

Each file has one of two layouts.

**Nothing recovered:** just the provider and why TDH failed.

```
provider	tdh_status
Microsoft-Windows-USB-CCID	2 ERROR_FILE_NOT_FOUND
```

**Events recovered:** the same columns as `manifest/`, plus `tdh_status` on every row.

```
provider	event_id	version	event(fields)	opcode	keywords	task	level	evtlog_channel	evtlog_message	tdh_status
Microsoft-Windows-WinML	3	0	NameStart3(Pointer pNet, UInt32 WinMLNetNameSize, AnsiString WinMLNetName)	Start	Perf	Name	Always	Microsoft-Windows-WinML/Analytic		15100 ERROR_MUI_FILE_NOT_FOUND
```

Captures from before `tdh_status` was added list only the provider name.

Reconstructed rows differ from the `manifest/` rows in these ways:

* **Names are the manifest's symbolic names.** TDH names tasks, opcodes and levels with their localized display strings, but those strings are usually what is missing. So WinML's task is `Name` (its real `name=` attribute) and its opcodes are `win:Start`/`win:Stop`. Event symbols are then built the same way TraceEvent builds them: task + opcode, a numeric suffix to keep them unique, and `_V<n>` for versions above 0.
* **`evtlog_message` is filled in only when the message string still resolves.** For the MUI-missing providers it's usually empty.
* **Event Log-era providers use 32-bit message ids**, `Severity|Facility|Code` (e.g. Volsnap's `0xC0060018`). `event_id` is the low 16 bits. That's what an ETW event descriptor carries and what Event Viewer shows as the Event ID.

## tdh_status

This is the result of [`TdhEnumerateManifestProviderEvents`](https://learn.microsoft.com/windows/win32/api/tdh/nf-tdh-tdhenumeratemanifestproviderevents) for the provider's GUID, called with no buffer. On success, TDH asks for a buffer (`122`). Any other value is the reason TDH can't give you the provider's events.

| tdh_status | What is actually wrong | Events recovered? |
|---|---|---|
| `15100 ERROR_MUI_FILE_NOT_FOUND` | The resource file is language-neutral, but its `.mui` satellite was never shipped. | Yes |
| `4306 ERROR_INVALID_OPERATION` | The manifest declares no events (with one exception, CertEnroll). | Usually none to recover |
| `1813 ERROR_RESOURCE_TYPE_NOT_FOUND` | The resource file has no `WEVT_TEMPLATE` resource. | No |
| `2 ERROR_FILE_NOT_FOUND` | The resource file doesn't exist. | No |
| `13 ERROR_INVALID_DATA` | The resource file's manifest doesn't contain this provider. | No |
| `122 ERROR_INSUFFICIENT_BUFFER` | Nothing on the TDH side. TraceEvent missed the events. | Yes |

The examples below were observed on Windows 11 build 26200.

### 15100 ERROR_MUI_FILE_NOT_FOUND

The resource file has a `WEVT_TEMPLATE` and an `MUI` resource. The `MUI` resource marks the file as language-neutral and says its strings live in a satellite `<file>.mui`. That satellite was never shipped, in any language.

TDH resolves a provider's strings (task, opcode, level and keyword names) together with its schema. It also sends even an explicitly loaded binary through the MUI loader. When the satellite is missing, every TDH call for the provider fails:

* enumeration returns `15100`;
* per-event lookups (`TdhGetManifestEventInformation`, `TdhGetEventInformation`) return `1168 ERROR_NOT_FOUND`, for every event id. Brute-forcing ids doesn't help.

There is no partial result. Stripping the `MUI` resource from a copy of the binary only changes the error. The copy has no message table, so it fails with `1813`. Adding an empty message table then fails with `317 ERROR_MR_MID_NOT_FOUND` on the first missing string.

Example: `Microsoft-Windows-WinML` is registered to `%SystemRoot%\system32\WinML.dll`, a 64 KB DLL with `WEVT_TEMPLATE` and `MUI` resources, no string or message table, and no `winml.dll.mui`.

**Events can be recovered.** The Event Log API reads the same template but only formats a string when asked for one. So the events, their templates and the symbolic names all survive. Only the localized text is lost.

To decode these events with TDH in your own consumer, you have to fake the schema. Rebuild a manifest XML from the Event Log metadata and load it with `TdhLoadManifest`. A loaded XML manifest takes precedence over the broken registration. A binary loaded with `TdhLoadManifestFromBinary` does not.

### 4306 ERROR_INVALID_OPERATION

The provider's manifest declares no events. Its `WEVT_TEMPLATE` has channels, keywords, levels and so on, but no `EVNT` element. For example, `ddisplay.dll` contains `CHAN PRVA OPCO LEVL TASK KEYW` only. These are registered for their channels or keywords, or the events are logged by a different provider. There is nothing to recover.

The exception is `Microsoft-Windows-CertificateServicesClient-CertEnroll`. It does declare 80 events, all with 32-bit Event Log message ids (facility `0x25A`). TDH's documented enumeration still returns `4306` for it, and we don't know why. The Event Log API reads all 80 events, so they are reconstructed here. See [122](#122-error_insufficient_buffer) for why TraceEvent also misses it.

### 1813 ERROR_RESOURCE_TYPE_NOT_FOUND

The registered resource file was found but has no `WEVT_TEMPLATE` resource. It may be a stub, or the template was never compiled into it. For example, `MFDshowReverseBridge.dll`, `drivers\bfs.sys` and `drivers\wdnisdrv.sys` have no template. Neither TDH nor the Event Log API has anything to read.

### 2 ERROR_FILE_NOT_FOUND

The registered resource file doesn't exist. Either the component isn't installed (e.g. `Microsoft-Windows-USB-CCID` → `drivers\UMDF\UsbccidDriver.dll`), or the registered path can't be resolved. For example, `Microsoft-Windows-SystemSettingsThreshold` is registered with a literal `$(runtime.windows)\ImmersiveControlPanel\SystemSettings.exe`.

### 13 ERROR_INVALID_DATA

The resource file exists and has a `WEVT_TEMPLATE`, but that template doesn't contain this provider's GUID. The registration points at the wrong binary. For example:

* `Microsoft-Windows-DxgKrnl-SysMm` (`{9de90b19-…}`) is registered to `drivers\dxgkrnl.sys`, whose manifest only contains `{802ec45a-…}`.
* `Microsoft-Windows-Privacy-Auditing-DiagnosticData` and `-TailoredExperiences` are registered to `diagtrack.dll`, whose manifest only contains `{6489b27f-…}` and `{030f2f57-…}`.

The Event Log API fails the same way, so nothing can be recovered from the registered file.

### 122 ERROR_INSUFFICIENT_BUFFER

TDH *can* read this manifest. `122` is the normal "give me a buffer" answer. These providers are here because of a TraceEvent 2.0.48 bug, not a TDH failure.

`RegisteredTraceEventParser.GetManifestForRegisteredProvider` doesn't use `TdhEnumerateManifestProviderEvents`. Instead, it calls the undocumented `TdhGetAllEventsInformation` once per event version, from 0 up to 255, and stops at the first `1168 ERROR_NOT_FOUND` after version 0. That assumes versions are contiguous from 0.

Event Log-era manifests with 32-bit message ids break that assumption. TDH files their events under a "version" equal to the low byte of the id's facility, so TraceEvent's scan stops before reaching them:

* `Volsnap`'s ids are `0x?006xxxx`, so its 62 events are only returned at version 6.
* CertEnroll's ids are `0x?25Axxxx`, so its events are only returned at version 90.

Current TraceEvent releases use `TdhEnumerateManifestProviderEvents` instead, which does read Volsnap.
