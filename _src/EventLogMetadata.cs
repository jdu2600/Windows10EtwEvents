using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Xml.Linq;

namespace DumpRegisteredEtwProviders
{
    /// <summary>One event, already rendered into the columns of a manifest tsv row.</summary>
    class ReconstructedEvent
    {
        public int Id;
        public int Version;
        public string Signature; // Symbol(Type Name, ...)
        public string Opcode;
        public string Keywords;
        public string Task;
        public string Level;
        public string Channel;
        public string Message;
    }

    /// <summary>
    /// Best-effort event metadata for providers that TDH (and therefore TraceEvent) cannot decode.
    /// </summary>
    /// <remarks>
    /// TDH resolves a registered publisher through its resource file AND its localized strings, and
    /// fails the whole provider when any string is missing - e.g. Microsoft-Windows-WinML ships a
    /// language-neutral WinML.dll whose winml.dll.mui never shipped, so TDH returns
    /// ERROR_MUI_FILE_NOT_FOUND for every event. The Event Log API (wevtapi) reads the same
    /// WEVT_TEMPLATE resource but only touches a string when it is asked for one, so the event
    /// descriptors, templates and the manifest's symbolic names are all still recoverable.
    ///
    /// This deliberately uses raw wevtapi rather than System.Diagnostics.Eventing.Reader:
    /// ProviderMetadata.Events formats every event's message while enumerating, so one missing
    /// string throws away the whole provider - the exact failure we are working around.
    /// </remarks>
    static class EventLogMetadata
    {
        /// <summary>
        /// The status TDH gives for this provider's manifest. ERROR_INSUFFICIENT_BUFFER (122) means
        /// TDH could read it; anything else is why TraceEvent produced nothing.
        /// </summary>
        public static int TdhStatus(Guid provider)
        {
            int size = 0;
            return TdhEnumerateManifestProviderEvents(ref provider, IntPtr.Zero, ref size);
        }

        /// <summary>"15100 ERROR_MUI_FILE_NOT_FOUND" - the code plus its winerror.h name, if known.</summary>
        public static string DescribeStatus(int status)
        {
            return StatusNames.TryGetValue(status, out var name) ? $"{status} {name}" : status.ToString();
        }

        // Every status seen across the unknown/ providers. unknown/README.md explains each one.
        private static readonly Dictionary<int, string> StatusNames = new Dictionary<int, string>
        {
            { 2, "ERROR_FILE_NOT_FOUND" },
            { 13, "ERROR_INVALID_DATA" },
            { 122, "ERROR_INSUFFICIENT_BUFFER" },
            { 1813, "ERROR_RESOURCE_TYPE_NOT_FOUND" },
            { 4306, "ERROR_INVALID_OPERATION" },
            { 15100, "ERROR_MUI_FILE_NOT_FOUND" },
        };

        /// <summary>
        /// Reconstructs every event the publisher's WEVT_TEMPLATE declares. Returns none if the Event
        /// Log API cannot open the publisher either.
        /// </summary>
        /// <remarks>
        /// Names follow TraceEvent's GetManifestForRegisteredProvider so that these rows read like
        /// the manifest/ ones - task + opcode, _V suffix, Always..Verbose, keyword_N for unnamed
        /// bits. The difference is that TraceEvent names things with their localized display
        /// strings, which is precisely what is missing here, so these use the manifest's symbolic
        /// names instead (task "Name" and opcode "win:Start" for WinML).
        /// </remarks>
        public static List<ReconstructedEvent> GetEvents(string providerName)
        {
            var result = new List<ReconstructedEvent>();
            var pm = EvtOpenPublisherMetadata(IntPtr.Zero, providerName, null, 0, 0);
            if (pm == IntPtr.Zero)
                return result;

            try
            {
                var tasks = ReadTable(pm, EvtPublisherMetadataTasks, EvtPublisherMetadataTaskName, EvtPublisherMetadataTaskValue);
                var opcodes = ReadTable(pm, EvtPublisherMetadataOpcodes, EvtPublisherMetadataOpcodeName, EvtPublisherMetadataOpcodeValue);
                var keywords = ReadTable(pm, EvtPublisherMetadataKeywords, EvtPublisherMetadataKeywordName, EvtPublisherMetadataKeywordValue);
                var channels = ReadChannels(pm);

                var taskNames = new Dictionary<string, int>();
                var opcodeNames = new Dictionary<string, int>();
                var eventNames = new Dictionary<string, int>();

                var en = EvtOpenEventMetadataEnum(pm, 0);
                if (en == IntPtr.Zero)
                    return result;
                try
                {
                    IntPtr em;
                    while ((em = EvtNextEventMetadata(en, 0)) != IntPtr.Zero)
                    {
                        try
                        {
                            // Event Log-era manifests (Volsnap, CertEnroll) use 32-bit message ids -
                            // Severity|Facility|Code, e.g. 0xC0060018. An ETW descriptor only carries the
                            // low 16 bits, which is also what Event Viewer shows as the Event ID.
                            var id = (int)(GetUInt32(em, EventMetadataEventID) & 0xFFFF);
                            var version = (int)GetUInt32(em, EventMetadataEventVersion);
                            var channel = (int)GetUInt32(em, EventMetadataEventChannel);
                            var level = (int)GetUInt32(em, EventMetadataEventLevel);
                            var opcode = (int)GetUInt32(em, EventMetadataEventOpcode);
                            var task = (int)GetUInt32(em, EventMetadataEventTask);
                            var keyword = GetUInt64(em, EventMetadataEventKeyword);
                            var messageId = GetUInt32(em, EventMetadataEventMessageID);
                            var template = GetString(em, EventMetadataEventTemplate);

                            // Opcodes are stored per task: the low word is the task, the high word the opcode.
                            var taskName = tasks.TryGetValue((ulong)task, out var t) ? LegalIdentifier(t) : $"task_{task}";
                            if (taskNames.TryGetValue(taskName, out var taskForName) && taskForName != task)
                                taskName = $"{taskName}_{task}";
                            taskNames[taskName] = task;

                            var opcodeName = string.Empty;
                            if (opcode != 0)
                            {
                                var opcodeKey = (ulong)(uint)opcode << 16;
                                if (opcodes.TryGetValue(opcodeKey | (uint)task, out var o) || opcodes.TryGetValue(opcodeKey, out o))
                                    opcodeName = LegalIdentifier(o.Substring(o.IndexOf(':') + 1));
                                else
                                    opcodeName = $"opcode_{opcode}";

                                if (opcodeNames.TryGetValue(opcodeName, out var opcodeForName) && opcodeForName != opcode)
                                    opcodeName = $"{opcodeName}_{task}_{opcode}";
                                opcodeNames[opcodeName] = opcode;
                            }

                            var eventName = taskName.EndsWith(opcodeName, StringComparison.OrdinalIgnoreCase)
                                ? taskName
                                : taskName + Capitalize(opcodeName);
                            if (eventNames.TryGetValue(eventName, out var idForName) && idForName != id)
                                eventName += id;
                            eventNames[eventName] = id;

                            var symbol = version > 0 ? $"{eventName}_V{version}" : eventName;

                            result.Add(new ReconstructedEvent
                            {
                                Id = id,
                                Version = version,
                                Signature = $"{symbol}({Fields(template)})",
                                Opcode = opcodeName,
                                Keywords = KeywordString(keywords, keyword),
                                Task = taskName,
                                Level = level <= LevelNames.Length - 1 ? LevelNames[level] : string.Empty,
                                Channel = channels.TryGetValue(channel, out var c) ? c : string.Empty,
                                Message = FormatMessage(pm, messageId),
                            });
                        }
                        finally
                        {
                            EvtClose(em);
                        }
                    }
                }
                finally
                {
                    EvtClose(en);
                }
            }
            finally
            {
                EvtClose(pm);
            }

            return result
                .OrderBy(e => e.Id)
                .ThenBy(e => e.Version)
                .ToList();
        }

        // TraceEventLevel names, which are what the manifest/ tsvs carry.
        private static readonly string[] LevelNames = { "Always", "Critical", "Error", "Warning", "Informational", "Verbose" };

        /// <summary>"UInt32 ProcessID, UnicodeString ImageName" from a wevtapi template.</summary>
        private static string Fields(string template)
        {
            if (string.IsNullOrEmpty(template))
                return string.Empty;

            var fields = new List<string>();
            foreach (var node in XElement.Parse(template).Elements())
            {
                var name = (string)node.Attribute("name");
                if (node.Name.LocalName == "struct")
                {
                    fields.Add($"Struct {name}");
                    continue;
                }

                var inType = (string)node.Attribute("inType") ?? string.Empty;
                fields.Add($"{inType.Substring(inType.IndexOf(':') + 1)} {name}");
            }

            return string.Join(", ", fields);
        }

        /// <summary>Keyword names for bits 0-47; bits 48-63 are reserved (channels etc.) and skipped, as TraceEvent does.</summary>
        private static string KeywordString(Dictionary<ulong, string> keywords, ulong keywordSet)
        {
            var names = new List<string>();
            for (var i = 0; i < 48; i++)
            {
                var keyword = 1UL << i;
                if ((keyword & keywordSet) == 0)
                    continue;
                // symbolic keyword names can contain spaces ("ioctl create query"), which would make
                // this space-separated list ambiguous - TraceEvent strips them too
                names.Add(keywords.TryGetValue(keyword, out var name) ? LegalIdentifier(name) : $"keyword_{keyword:x}");
            }

            return string.Join(" ", names);
        }

        /// <summary>The event message, or empty - for these providers it is usually the missing string.</summary>
        private static string FormatMessage(IntPtr pm, uint messageId)
        {
            if (messageId == uint.MaxValue)
                return string.Empty;

            var buffer = new StringBuilder(4096);
            if (!EvtFormatMessage(pm, IntPtr.Zero, messageId, 0, IntPtr.Zero, EvtFormatMessageId, buffer.Capacity, buffer, out var used))
            {
                if (Marshal.GetLastWin32Error() != ERROR_INSUFFICIENT_BUFFER)
                    return string.Empty;
                buffer = new StringBuilder(used);
                if (!EvtFormatMessage(pm, IntPtr.Zero, messageId, 0, IntPtr.Zero, EvtFormatMessageId, buffer.Capacity, buffer, out used))
                    return string.Empty;
            }

            return buffer.ToString().Trim().Replace("\r", @"\r").Replace("\n", @"\n").Replace("\t", @"\t");
        }

        private static string LegalIdentifier(string name)
        {
            return name.Replace(" ", "").Replace("-", "_");
        }

        private static string Capitalize(string name)
        {
            return name.Length == 0 || char.IsUpper(name[0]) ? name : char.ToUpper(name[0]) + name.Substring(1);
        }

        /// <summary>value -> symbolic name, for one of the publisher's task/opcode/keyword tables.</summary>
        private static Dictionary<ulong, string> ReadTable(IntPtr pm, int arrayProperty, int nameProperty, int valueProperty)
        {
            var table = new Dictionary<ulong, string>();
            var array = GetPublisherProperty(pm, arrayProperty);
            if (array.Type != EvtVarTypeEvtHandle || array.Handle == IntPtr.Zero)
                return table;
            try
            {
                if (!EvtGetObjectArraySize(array.Handle, out var count))
                    return table;
                for (var i = 0; i < count; i++)
                {
                    var name = GetArrayProperty(array.Handle, nameProperty, i);
                    var value = GetArrayProperty(array.Handle, valueProperty, i);
                    var key = value.Type == EvtVarTypeUInt64 || value.Type == EvtVarTypeHexInt64 ? value.UInt64 : value.UInt32;
                    if (name.Type == EvtVarTypeString && !table.ContainsKey(key))
                        table[key] = name.String;
                }
            }
            finally
            {
                EvtClose(array.Handle);
            }

            return table;
        }

        /// <summary>channel value -> channel path, e.g. 16 -> Microsoft-Windows-WinML/Analytic.</summary>
        private static Dictionary<int, string> ReadChannels(IntPtr pm)
        {
            var channels = new Dictionary<int, string>();
            var array = GetPublisherProperty(pm, EvtPublisherMetadataChannelReferences);
            if (array.Type != EvtVarTypeEvtHandle || array.Handle == IntPtr.Zero)
                return channels;
            try
            {
                if (!EvtGetObjectArraySize(array.Handle, out var count))
                    return channels;
                for (var i = 0; i < count; i++)
                {
                    var path = GetArrayProperty(array.Handle, EvtPublisherMetadataChannelReferencePath, i);
                    var value = GetArrayProperty(array.Handle, EvtPublisherMetadataChannelReferenceID, i);
                    if (path.Type == EvtVarTypeString && !channels.ContainsKey((int)value.UInt32))
                        channels[(int)value.UInt32] = path.String;
                }
            }
            finally
            {
                EvtClose(array.Handle);
            }

            return channels;
        }

        #region wevtapi / tdh interop

        /// <summary>The parts of an EVT_VARIANT this class reads, copied out of the native buffer.</summary>
        private struct Variant
        {
            public uint Type;
            public uint UInt32;
            public ulong UInt64;
            public IntPtr Handle;
            public string String;
        }

        private delegate bool PropertyGetter(int bufferSize, IntPtr buffer, out int used);

        /// <summary>Calls a wevtapi property getter with a right-sized buffer and decodes the EVT_VARIANT.</summary>
        private static Variant GetProperty(PropertyGetter getter)
        {
            getter(0, IntPtr.Zero, out var used);
            var buffer = Marshal.AllocHGlobal(Math.Max(used, 16));
            try
            {
                if (!getter(Math.Max(used, 16), buffer, out used))
                    throw new Win32Exception();

                // EVT_VARIANT: an 8-byte value union, then DWORD Count, then DWORD Type.
                var type = (uint)Marshal.ReadInt32(buffer, 12) & 0x7f;
                var raw = Marshal.ReadInt64(buffer, 0);
                return new Variant
                {
                    Type = type,
                    UInt32 = (uint)raw,
                    UInt64 = (ulong)raw,
                    Handle = type == EvtVarTypeEvtHandle ? (IntPtr)raw : IntPtr.Zero,
                    String = type == EvtVarTypeString ? Marshal.PtrToStringUni((IntPtr)raw) : null,
                };
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static Variant GetPublisherProperty(IntPtr pm, int id)
        {
            try { return GetProperty((int s, IntPtr b, out int u) => EvtGetPublisherMetadataProperty(pm, id, 0, s, b, out u)); }
            catch (Win32Exception) { return new Variant { Type = EvtVarTypeNull }; }
        }

        private static Variant GetArrayProperty(IntPtr array, int id, int index)
        {
            try { return GetProperty((int s, IntPtr b, out int u) => EvtGetObjectArrayProperty(array, id, index, 0, s, b, out u)); }
            catch (Win32Exception) { return new Variant { Type = EvtVarTypeNull }; }
        }

        private static uint GetUInt32(IntPtr em, int id) => GetProperty((int s, IntPtr b, out int u) => EvtGetEventMetadataProperty(em, id, 0, s, b, out u)).UInt32;
        private static ulong GetUInt64(IntPtr em, int id) => GetProperty((int s, IntPtr b, out int u) => EvtGetEventMetadataProperty(em, id, 0, s, b, out u)).UInt64;
        private static string GetString(IntPtr em, int id) => GetProperty((int s, IntPtr b, out int u) => EvtGetEventMetadataProperty(em, id, 0, s, b, out u)).String;

        private const int ERROR_INSUFFICIENT_BUFFER = 122;

        // EVT_VARIANT_TYPE
        private const uint EvtVarTypeNull = 0;
        private const uint EvtVarTypeString = 1;
        private const uint EvtVarTypeUInt64 = 10;
        private const uint EvtVarTypeHexInt64 = 21;
        private const uint EvtVarTypeEvtHandle = 32;

        // EVT_EVENT_METADATA_PROPERTY_ID
        private const int EventMetadataEventID = 0;
        private const int EventMetadataEventVersion = 1;
        private const int EventMetadataEventChannel = 2;
        private const int EventMetadataEventLevel = 3;
        private const int EventMetadataEventOpcode = 4;
        private const int EventMetadataEventTask = 5;
        private const int EventMetadataEventKeyword = 6;
        private const int EventMetadataEventMessageID = 7;
        private const int EventMetadataEventTemplate = 8;

        // EVT_PUBLISHER_METADATA_PROPERTY_ID
        private const int EvtPublisherMetadataChannelReferences = 6;
        private const int EvtPublisherMetadataChannelReferencePath = 7;
        private const int EvtPublisherMetadataChannelReferenceID = 9;
        private const int EvtPublisherMetadataTasks = 16;
        private const int EvtPublisherMetadataTaskName = 17;
        private const int EvtPublisherMetadataTaskValue = 19;
        private const int EvtPublisherMetadataOpcodes = 21;
        private const int EvtPublisherMetadataOpcodeName = 22;
        private const int EvtPublisherMetadataOpcodeValue = 23;
        private const int EvtPublisherMetadataKeywords = 25;
        private const int EvtPublisherMetadataKeywordName = 26;
        private const int EvtPublisherMetadataKeywordValue = 27;

        // EVT_FORMAT_MESSAGE_FLAGS
        private const int EvtFormatMessageId = 8;

        [DllImport("tdh.dll")]
        private static extern int TdhEnumerateManifestProviderEvents(ref Guid provider, IntPtr buffer, ref int bufferSize);

        [DllImport("wevtapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr EvtOpenPublisherMetadata(IntPtr session, string publisherId, string logFilePath, int locale, int flags);

        [DllImport("wevtapi.dll", SetLastError = true)]
        private static extern IntPtr EvtOpenEventMetadataEnum(IntPtr publisherMetadata, int flags);

        [DllImport("wevtapi.dll", SetLastError = true)]
        private static extern IntPtr EvtNextEventMetadata(IntPtr eventMetadataEnum, int flags);

        [DllImport("wevtapi.dll", SetLastError = true)]
        private static extern bool EvtGetEventMetadataProperty(IntPtr eventMetadata, int propertyId, int flags, int bufferSize, IntPtr buffer, out int bufferUsed);

        [DllImport("wevtapi.dll", SetLastError = true)]
        private static extern bool EvtGetPublisherMetadataProperty(IntPtr publisherMetadata, int propertyId, int flags, int bufferSize, IntPtr buffer, out int bufferUsed);

        [DllImport("wevtapi.dll", SetLastError = true)]
        private static extern bool EvtGetObjectArraySize(IntPtr objectArray, out int objectArraySize);

        [DllImport("wevtapi.dll", SetLastError = true)]
        private static extern bool EvtGetObjectArrayProperty(IntPtr objectArray, int propertyId, int arrayIndex, int flags, int bufferSize, IntPtr buffer, out int bufferUsed);

        [DllImport("wevtapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool EvtFormatMessage(IntPtr publisherMetadata, IntPtr evt, uint messageId, int valueCount, IntPtr values, int flags, int bufferSize, StringBuilder buffer, out int bufferUsed);

        [DllImport("wevtapi.dll")]
        private static extern bool EvtClose(IntPtr handle);

        #endregion
    }
}
