using System;
using System.Collections.Generic;

namespace EtwManifestParsing
{
    /// <summary>
    /// The names published for one provider's events: the event symbol and the task and opcode
    /// columns. TdhManifestReader (manifest/) and EventLogMetadata (unknown/) both use it, so the two
    /// folders name events the same way.
    /// </summary>
    /// <remarks>
    /// Where the manifest names the task, events keep TraceEvent's task + opcode names. Otherwise
    /// they are Event_&lt;id&gt;[_&lt;opcode&gt;][_V&lt;version&gt;], like the Task_Opcode names of the MOF
    /// providers - or Message_0x&lt;message id&gt; for an Event Log-era event. These match PerfView #2483.
    ///
    /// Event Log-era events (win:EventlogClassic) keep a 32-bit message id - Severity|C|R|Facility|Code -
    /// and the manifest compiler packs it into the descriptor: Id = bits 0-15, Version = bits 16-23,
    /// Opcode = bits 24-31 (the full id is stored alongside). They are named as wevtapi and the event
    /// log present them: the code as the id, version 0 and no opcode, named by the whole message id.
    ///
    /// Names depend on the events named before them (to keep them unique), so use one EventNamer per
    /// provider and feed it the events in a stable order.
    /// </remarks>
    public sealed class EventNamer
    {
        /// <summary>win:EventlogClassic - set on every event that keeps an Event Log message id.</summary>
        public const ulong EventlogClassicKeyword = 0x80000000000000UL;

        public sealed class Names
        {
            public string Symbol;   // including any _V suffix
            public string Task;     // the task column
            public string Opcode;   // the opcode column
            public int Version;     // the version column
        }

        private readonly Dictionary<string, int> _taskNames = new Dictionary<string, int>();
        private readonly Dictionary<string, int> _opcodeNames = new Dictionary<string, int>();
        private readonly Dictionary<string, int> _eventNames = new Dictionary<string, int>();
        private readonly Dictionary<string, uint> _classicNames = new Dictionary<string, uint>();

        /// <param name="id">The event id - for a classic event, the code (low 16 bits of the message id).</param>
        /// <param name="taskName">The name the metadata gives the task, or null if it gives none.</param>
        /// <param name="opcodeName">The name the metadata gives the opcode, or null if it gives none.</param>
        /// <param name="classicMessageId">The full message id of a win:EventlogClassic event, else null.
        /// Its version and opcode are then the packed parts of that id, and are ignored.</param>
        public Names Name(int id, int version, int task, string taskName, int opcode, string opcodeName, uint? classicMessageId)
        {
            if (classicMessageId.HasValue)
            {
                version = 0;
                opcode = 0;
            }

            // Task name, unique per task value
            var taskColumn = taskName != null ? MakeLegalIdentifier(taskName) : $"task_{task}";
            if (_taskNames.TryGetValue(taskColumn, out var taskForName) && taskForName != task)
                taskColumn = $"{taskColumn}_{task}";
            _taskNames[taskColumn] = task;

            // Opcode name, unique per opcode value
            var opcodeLabel = string.Empty;
            if (opcode != 0)
                opcodeLabel = opcodeName != null ? MakeLegalIdentifier(opcodeName) : $"opcode_{opcode}";
            if (_opcodeNames.TryGetValue(opcodeLabel, out var opcodeForName) && opcodeForName != opcode)
                opcodeLabel = $"{(opcodeName == null ? "opcode" : opcodeLabel)}_{task}_{opcode}";
            _opcodeNames[opcodeLabel] = opcode;

            string eventName;
            if (taskName != null)
            {
                // A named task: TraceEvent's task + opcode, unique per event id
                eventName = taskColumn;
                if (!taskColumn.EndsWith(opcodeLabel, StringComparison.OrdinalIgnoreCase))
                    eventName += Capitalize(opcodeLabel);
                if (_eventNames.TryGetValue(eventName, out var idForName) && idForName != id)
                    eventName += id;
            }
            else if (classicMessageId.HasValue)
            {
                // A classic event is identified by its whole message id - unique, and it keeps the
                // severity and facility that the code alone drops (as in PerfView #2483)
                eventName = $"Message_0x{classicMessageId.Value:X8}";
            }
            else
            {
                eventName = $"Event_{id}";
                if (opcode != 0)
                    eventName += "_" + (opcodeName != null ? opcodeLabel : $"Opcode{opcode}");
            }
            _eventNames[eventName] = id;

            if (classicMessageId.HasValue && taskName != null)
            {
                // A classic event with a named task (none seen so far) is named like any other; its
                // message id keeps it unique if another classic event has the same name.
                if (_classicNames.TryGetValue(eventName, out var other) && other != classicMessageId.Value)
                    eventName += $"_Message_0x{classicMessageId.Value:X8}";
                _classicNames[eventName] = classicMessageId.Value;
            }

            // The manifest opcode attribute was "win:<name>" for the reserved opcodes (< 10), and just
            // the name otherwise; the published column kept what followed the first ':'.
            var opcodeColumn = string.Empty;
            if (opcode == DataCollectionStart)
                opcodeColumn = "DC_Start";
            else if (opcode == DataCollectionStop)
                opcodeColumn = "DC_Stop";
            else if (opcode != 0 && opcode < 10)
                opcodeColumn = opcodeLabel;
            else if (opcode != 0)
                opcodeColumn = opcodeLabel.Substring(opcodeLabel.IndexOf(':') + 1);

            return new Names
            {
                Symbol = version > 0 ? $"{eventName}_V{version}" : eventName,
                Task = taskColumn,
                Opcode = opcodeColumn,
                Version = version,
            };
        }

        /// <summary>Spaces and dashes don't belong in an identifier (or in a space-separated keyword list).</summary>
        public static string MakeLegalIdentifier(string name)
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


        private const int DataCollectionStart = 3;
        private const int DataCollectionStop = 4;
    }
}
