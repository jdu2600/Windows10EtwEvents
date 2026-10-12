using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace EtwManifestParsing
{
    /// <summary>
    /// Reads the metadata of registered (manifest-based) ETW providers straight from TDH.
    /// </summary>
    /// <remarks>
    /// This replaces TraceEvent's RegisteredTraceEventParser.GetManifestForRegisteredProvider, which
    /// rendered the same TDH structures as manifest XML for ManifestParser to read back. Both TraceEvent
    /// generations lost events:
    ///
    /// * 2.0.48 asked TdhGetAllEventsInformation for versions 0, 1, 2... and stopped at the first
    ///   missing version after 0, so every event above a gap in the version numbers was dropped -
    ///   all of Volsnap, whose packed Event Log message ids put them at version 6.
    /// * 3.x lists descriptors with TdhEnumerateManifestProviderEvents and looks each one up with
    ///   TdhGetManifestEventInformation, which matches on id+version only. Event Log-era manifests
    ///   can declare two events that differ only in the severity bits of a 32-bit message id
    ///   (MSDTC 0x8000D01A / 0xC000D01A) - the descriptor carries those bits as the opcode - and
    ///   the lookup returns the first event's fields for both.
    ///
    /// TdhGetAllEventsInformation returns each event's own TRACE_EVENT_INFO, so it is asked about
    /// every version, gaps and all.
    ///
    /// Names follow TraceEvent (task + opcode) where the manifest names the task. Otherwise they
    /// are Event_&lt;id&gt;[_&lt;opcode&gt;][_&lt;severity&gt;][_V&lt;version&gt;].
    /// </remarks>
    public static class TdhManifestReader
    {
        /// <summary>
        /// Every provider TDH knows about (manifest and MOF), as (guid, name), in name order.
        /// </summary>
        /// <remarks>
        /// TraceEvent keyed this list by name, case-insensitively, so a name registered under two
        /// GUIDs keeps only the last - and walked it in name order. Both are kept: the order decides
        /// which provider's tsv survives when two names map to the same file name.
        /// </remarks>
        public static IReadOnlyList<KeyValuePair<Guid, string>> GetPublishedProviders()
        {
            if (_providers != null)
                return _providers;

            var byName = new SortedDictionary<string, Guid>(StringComparer.OrdinalIgnoreCase);
            var size = 0;
            TdhEnumerateProviders(IntPtr.Zero, ref size);
            var buffer = Marshal.AllocHGlobal(Math.Max(size, 8));
            try
            {
                if (TdhEnumerateProviders(buffer, ref size) == 0)
                {
                    // PROVIDER_ENUMERATION_INFO: NumberOfProviders, Reserved, then TRACE_PROVIDER_INFO[]
                    // TRACE_PROVIDER_INFO: GUID ProviderGuid, ULONG SchemaSource, ULONG ProviderNameOffset
                    var count = Marshal.ReadInt32(buffer, 0);
                    for (var i = 0; i < count; i++)
                    {
                        var entry = 8 + i * 24;
                        var guid = ReadGuid(buffer, entry);
                        var name = Marshal.PtrToStringUni(buffer + Marshal.ReadInt32(buffer, entry + 20));
                        byName[name] = guid;
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }

            var byGuid = new Dictionary<Guid, string>();
            foreach (var entry in byName)
                byGuid[entry.Value] = entry.Key;
            _providers = byGuid.ToList();
            return _providers;
        }

        private static List<KeyValuePair<Guid, string>> _providers;

        /// <summary>
        /// The provider's keywords as (mask, name), from TdhEnumerateProviderFieldInformation. None if
        /// TDH has no field information for it; throws if TDH reports some but then fails to return them.
        /// </summary>
        private static List<KeyValuePair<ulong, string>> GetProviderKeywords(Guid provider)
        {
            var keywords = new List<KeyValuePair<ulong, string>>();
            var size = 0;
            if (TdhEnumerateProviderFieldInformation(ref provider, EventKeywordInformation, IntPtr.Zero, ref size) != ERROR_INSUFFICIENT_BUFFER)
                return keywords;

            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                if (TdhEnumerateProviderFieldInformation(ref provider, EventKeywordInformation, buffer, ref size) != 0)
                    throw new InvalidOperationException($"Provider with ID {provider} not found.");

                // PROVIDER_FIELD_INFOARRAY: NumberOfElements, FieldType, then PROVIDER_FIELD_INFO[]
                // PROVIDER_FIELD_INFO: ULONG NameOffset, ULONG DescriptionOffset, ULONGLONG Value
                var count = Marshal.ReadInt32(buffer, 0);
                for (var i = 0; i < count; i++)
                {
                    var entry = 8 + i * 16;
                    keywords.Add(new KeyValuePair<ulong, string>(
                        (ulong)Marshal.ReadInt64(buffer, entry + 8),
                        Marshal.PtrToStringUni(buffer + Marshal.ReadInt32(buffer, entry))));
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }

            return keywords;
        }

        /// <summary>
        /// Every event TDH can decode for this provider. Throws ApplicationException if there are none -
        /// which is how a provider ends up in unknown/.
        /// </summary>
        public static EtwManifest GetManifest(Guid provider)
        {
            // TraceEvent compared against 1000000000000 (decimal), not a bit position - kept as is.
            var keywords = new SortedDictionary<ulong, string>();
            foreach (var keyword in GetProviderKeywords(provider))
            {
                if (keyword.Key < 1000000000000UL)
                    keywords[keyword.Key] = MakeLegalIdentifier(keyword.Value);
            }

            var taskNames = new Dictionary<string, int>();
            var opcodeNames = new Dictionary<string, int>();
            var eventNames = new Dictionary<string, int>();
            var templates = new List<EtwTemplate>();
            // grouped by event id (as the manifest XML was), in the order TDH returned them
            var events = new SortedDictionary<int, List<EtwEvent>>();

            var classicNames = new Dictionary<string, uint>();

            foreach (var info in GetAllEventsInformation(provider))
            {
                // Event Log-era events keep their 32-bit message id - Severity|C|R|Facility|Code - and
                // the manifest compiler packs it into the descriptor: Id = bits 0-15, Version = bits
                // 16-23, Opcode = bits 24-31 (the full id is stored alongside). Unpack it, as wevtapi
                // does and as the event log records these events: the code as the id, version 0, no
                // opcode, and the severity in the name.
                var classic = (info.Keyword & EventlogClassicKeyword) != 0;
                var messageId = ((uint)info.Opcode << 24) | ((uint)info.Version << 16) | (uint)info.Id;
                var version = classic ? 0 : info.Version;
                var opcodeValue = classic ? 0 : info.Opcode;

                // Task name, unique per task value
                var taskName = info.TaskName != null ? MakeLegalIdentifier(info.TaskName) : $"task_{info.Task}";
                if (taskNames.TryGetValue(taskName, out var taskForName) && taskForName != info.Task)
                    taskName = $"{taskName}_{info.Task}";
                taskNames[taskName] = info.Task;

                // Opcode name, unique per opcode value
                var opcodeName = string.Empty;
                if (opcodeValue != 0)
                    opcodeName = info.OpcodeName != null ? MakeLegalIdentifier(info.OpcodeName) : $"opcode_{opcodeValue}";
                if (opcodeNames.TryGetValue(opcodeName, out var opcodeForName) && opcodeForName != opcodeValue)
                    opcodeName = $"{(info.OpcodeName == null ? "opcode" : opcodeName)}_{info.Task}_{opcodeValue}";
                opcodeNames[opcodeName] = opcodeValue;

                string eventName;
                if (info.TaskName != null)
                {
                    // A named task: TraceEvent's task + opcode, unique per event id
                    eventName = taskName;
                    if (!taskName.EndsWith(opcodeName, StringComparison.OrdinalIgnoreCase))
                        eventName += Capitalize(opcodeName);
                    if (eventNames.TryGetValue(eventName, out var idForName) && idForName != info.Id)
                        eventName += info.Id;
                }
                else
                {
                    // No task name, so nothing better than the id - Event_43007_Start, like the
                    // Task_Opcode names of the MOF providers
                    eventName = $"Event_{info.Id}";
                    if (opcodeValue != 0)
                        eventName += "_" + (info.OpcodeName != null ? opcodeName : $"Opcode{opcodeValue}");
                }
                eventNames[eventName] = info.Id;

                if (classic)
                {
                    var severity = (int)(messageId >> 30);
                    if (severity != 0)
                        eventName += "_" + SeverityNames[severity];
                    // Two classic events can share a code and a severity in different facilities.
                    if (classicNames.TryGetValue(eventName, out var other) && other != messageId)
                        eventName += $"_Facility{(messageId >> 16) & 0xFFF:X}";
                    classicNames[eventName] = messageId;
                }

                var symbol = version > 0 ? $"{eventName}_V{version}" : eventName;

                // The manifest opcode attribute was "win:<name>" for the reserved opcodes (< 10), and
                // just the name otherwise. ManifestParser kept what followed the first ':'.
                var opcode = string.Empty;
                if (opcodeValue == DataCollectionStart)
                    opcode = "DC_Start";
                else if (opcodeValue == DataCollectionStop)
                    opcode = "DC_Stop";
                else if (opcodeValue != 0 && opcodeValue < 10)
                    opcode = opcodeName;
                else if (opcodeValue != 0)
                    opcode = opcodeName.Substring(opcodeName.IndexOf(':') + 1);

                string templateId = null;
                if (info.Fields.Length != 0)
                {
                    // one template per event: colliding events can share a symbol but not their fields
                    templateId = $"T{templates.Count}";
                    templates.Add(new EtwTemplate(templateId, info.Fields));
                }

                if (!events.TryGetValue(info.Id, out var sameId))
                    events[info.Id] = sameId = new List<EtwEvent>();
                sameId.Add(new EtwEvent
                {
                    Value = info.Id,
                    Symbol = symbol,
                    Version = version,
                    Opcode = opcode,
                    Level = info.Level <= LevelNames.Length - 1 ? LevelNames[info.Level] : string.Empty,
                    Keyword = KeywordString(keywords, info.Keyword),
                    Task = taskName,
                    Template = templateId,
                });
            }

            if (events.Count == 0)
                throw new ApplicationException($"Could not find provider with at GUID of {provider}");

            return new EtwManifest
            {
                Events = events.Values.SelectMany(e => e).ToArray(),
                Templates = templates.ToArray(),
            };
        }

        // TraceEventLevel names, as published
        private static readonly string[] LevelNames = { "Always", "Critical", "Error", "Warning", "Informational", "Verbose" };

        // the top two bits of an Event Log message id
        private static readonly string[] SeverityNames = { "Success", "Informational", "Warning", "Error" };

        // win:EventlogClassic - set on every event that keeps an Event Log message id
        private const ulong EventlogClassicKeyword = 0x80000000000000UL;

        private const int DataCollectionStart = 3;
        private const int DataCollectionStop = 4;

        /// <summary>Space-separated names for keyword bits 0-47; unnamed bits become keyword_&lt;hex&gt;.</summary>
        private static string KeywordString(SortedDictionary<ulong, string> keywords, ulong keywordSet)
        {
            var names = new List<string>();
            for (var i = 0; i < 48; i++)
            {
                var keyword = 1UL << i;
                if ((keyword & keywordSet) == 0)
                    continue;
                if (!keywords.TryGetValue(keyword, out var name))
                    keywords[keyword] = name = $"keyword_{keyword:x}";
                names.Add(name);
            }

            return names.Count == 0 ? null : string.Join(" ", names);
        }

        private static string MakeLegalIdentifier(string name)
        {
            return name.Replace(" ", "").Replace("-", "_");
        }

        /// <summary>
        /// "opcodeError" -> "OpcodeError". (TraceEvent's version returned
        /// name.Substring(1).ToUpper() + name.Substring(1), i.e. "PCODEERRORpcodeError".)
        /// </summary>
        private static string Capitalize(string name)
        {
            if (name.Length == 0 || char.IsUpper(name[0]))
                return name;
            return char.ToUpper(name[0]) + name.Substring(1);
        }

        /// <summary>The parts of one TRACE_EVENT_INFO that the tsvs use.</summary>
        private sealed class EventInfo
        {
            public int Id, Version, Level, Opcode, Task;
            public ulong Keyword;
            public string TaskName, OpcodeName;
            public EtwTemplateData[] Fields;
        }

        /// <summary>
        /// TdhGetAllEventsInformation for every event version, 0-255, in that order.
        /// </summary>
        /// <remarks>
        /// Asking about every version, rather than only those TdhEnumerateManifestProviderEvents
        /// lists, is not just simpler: that enumeration misses events. It never lists
        /// Microsoft-AppV-Client-StreamingUX event 9 (versions 22-24) or Microsoft-Windows-MSMPEG2VDEC
        /// event 13 (version 12), and for CertEnroll it reports ERROR_EMPTY (no events),
        /// whose packed message ids put its events at version 90.
        /// </remarks>
        private static IEnumerable<EventInfo> GetAllEventsInformation(Guid provider)
        {
            var record = Marshal.AllocHGlobal(EventRecordSize);
            var size = 84000;
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                for (var version = 0; version <= 255; version++)
                {
                    // An EVENT_RECORD that names only the provider and the version
                    for (var i = 0; i < EventRecordSize; i += 8)
                        Marshal.WriteInt64(record, i, 0);
                    Marshal.Copy(provider.ToByteArray(), 0, record + EventHeaderProviderId, 16);
                    Marshal.WriteByte(record, EventHeaderVersion, (byte)version);

                    int status, count;
                    while (true)
                    {
                        status = TdhGetAllEventsInformation(record, IntPtr.Zero, out _, out count, buffer, ref size);
                        if (status != ERROR_INSUFFICIENT_BUFFER)
                            break;
                        Marshal.FreeHGlobal(buffer);
                        buffer = Marshal.AllocHGlobal(size);
                    }

                    if (status != 0)
                        continue;

                    // the buffer starts with count PTRACE_EVENT_INFO pointers into itself
                    for (var i = 0; i < count; i++)
                        yield return ReadEventInfo(Marshal.ReadIntPtr(buffer, i * IntPtr.Size));
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
                Marshal.FreeHGlobal(record);
            }
        }

        private static EventInfo ReadEventInfo(IntPtr info)
        {
            // TRACE_EVENT_INFO: ProviderGuid, EventGuid, EVENT_DESCRIPTOR @32, DecodingSource @48,
            // ...NameOffsets..., TaskNameOffset @68, OpcodeNameOffset @72, ...,
            // TopLevelPropertyCount @104, Flags @108, EVENT_PROPERTY_INFO[] @112
            var result = new EventInfo
            {
                Id = (ushort)Marshal.ReadInt16(info, 32),
                Version = Marshal.ReadByte(info, 34),
                Level = Marshal.ReadByte(info, 36),
                Opcode = Marshal.ReadByte(info, 37),
                Task = (ushort)Marshal.ReadInt16(info, 38),
                Keyword = (ulong)Marshal.ReadInt64(info, 40),
                TaskName = StringAt(info, Marshal.ReadInt32(info, 68)),
                OpcodeName = StringAt(info, Marshal.ReadInt32(info, 72)),
            };

            var properties = Marshal.ReadInt32(info, 104);
            result.Fields = new EtwTemplateData[properties];
            for (var j = 0; j < properties; j++)
            {
                // EVENT_PROPERTY_INFO (24 bytes): Flags, NameOffset, InType @8, ...
                // InType is read even for structs, where those bytes are StructStartIndex - as TraceEvent did.
                var property = info + 112 + j * 24;
                var inType = (TdhInputType)(ushort)Marshal.ReadInt16(property, 8);
                result.Fields[j] = new EtwTemplateData
                {
                    // names were reduced to identifier characters for the manifest XML
                    Name = Regex.Replace(StringAt(info, Marshal.ReadInt32(property, 4)) ?? string.Empty, "[^A-Za-z0-9_]", ""),
                    Type = inType.ToString(),
                };
            }

            return result;
        }

        private static string StringAt(IntPtr info, int offset)
        {
            return offset == 0 ? null : Marshal.PtrToStringUni(info + offset);
        }

        private static Guid ReadGuid(IntPtr buffer, int offset)
        {
            var bytes = new byte[16];
            Marshal.Copy(buffer + offset, bytes, 0, 16);
            return new Guid(bytes);
        }

        /// <summary>TDH_IN_TYPE, with the names TraceEvent 2.0.48 printed (unnamed values print as numbers).</summary>
        private enum TdhInputType : ushort
        {
            Null, UnicodeString, AnsiString, Int8, UInt8, Int16, UInt16, Int32, UInt32, Int64, UInt64,
            Float, Double, Boolean, Binary, GUID, Pointer, FILETIME, SYSTEMTIME, SID, HexInt32, HexInt64,
            CountedUtf16String, CountedMbcsString, Struct,
            CountedString = 300, CountedAnsiString, ReversedCountedString, ReversedCountedAnsiString,
            NonNullTerminatedString, NonNullTerminatedAnsiString, UnicodeChar, AnsiChar, SizeT, HexDump, WbemSID,
        }

        private const int ERROR_INSUFFICIENT_BUFFER = 122;
        private const int EventKeywordInformation = 0; // EVENT_FIELD_TYPE

        // EVENT_RECORD on x64: EVENT_HEADER (80), ETW_BUFFER_CONTEXT (4), two USHORTs, three pointers.
        // The generator always runs 64-bit (Prefer32Bit=false, see 5fb19b5).
        private const int EventRecordSize = 112;
        private const int EventHeaderProviderId = 24;
        private const int EventHeaderVersion = 40 + 2; // EVENT_DESCRIPTOR @40: Id, then Version

        [DllImport("tdh.dll")]
        private static extern int TdhEnumerateProviders(IntPtr buffer, ref int bufferSize);

        [DllImport("tdh.dll")]
        private static extern int TdhEnumerateProviderFieldInformation(ref Guid provider, int fieldType, IntPtr buffer, ref int bufferSize);

        /// <summary>Exported from tdh.dll but not declared in any SDK header.</summary>
        [DllImport("tdh.dll")]
        private static extern int TdhGetAllEventsInformation(IntPtr eventRecord, IntPtr wbemService, out int index, out int count, IntPtr buffer, ref int bufferSize);
    }
}
