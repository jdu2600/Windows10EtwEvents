using Microsoft.Diagnostics.Tracing.Session;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace EtwManifestParsing
{
    public static class ManifestParser
    {
        // EventTypeName, DisplayName and Description are *amended* qualifiers: WMI keeps them
        // in the locale namespace (root\wmi\ms_409) and does not return them unless you ask.
        // Without this, Process_V4_TypeGroup1 looks like it has no opcode names at all, when
        // in fact it carries EventTypeName{"Start", "End", "DCStart", "DCEnd", "Defunct"} -
        // which is where TDH gets the names it displays.
        private static EnumerationOptions AmendedQualifiers => new EnumerationOptions { UseAmendedQualifiers = true };

        // Generic opcodes from evntrace.h, used only when a class declares no EventTypeName
        // for an opcode. Where evntrace.h gives two names for one value (End/Stop,
        // Dequeue/Resume, Checkpoint/Suspend) the classic ETW spelling is used. 0x0A/0x0B are
        // the Process/Thread convention rather than truly generic, but no other provider
        // assigns them a conflicting meaning.
        private static readonly Dictionary<int, string> StandardOpcodeNames = new Dictionary<int, string>
        {
            { 0x00, "Info" }, { 0x01, "Start" }, { 0x02, "End" }, { 0x03, "DCStart" },
            { 0x04, "DCEnd" }, { 0x05, "Extension" }, { 0x06, "Reply" }, { 0x07, "Dequeue" },
            { 0x08, "Checkpoint" }, { 0x09, "WinEvtSend" }, { 0x0A, "Load" },
            { 0x0B, "Terminate" }, { 0xF0, "WinEvtReceive" },
        };

        private static readonly Regex VersionSuffix = new Regex(@"^(?<Name>.+)_V\d+$");

        // Every EventTrace subclass on this machine, indexed by its Guid class qualifier.
        // Built once - the query takes ~1s, and we are asked about every registered provider,
        // the vast majority of which are manifest-based and have no MOF here at all.
        private static Dictionary<Guid, ManagementClass> _providerClasses;

        public static EtwManifest Parse(XElement element)
        {
            var manifest = new EtwManifest(element.ToString());
            try
            {
                var ns = element.GetDefaultNamespace();

                var stringTable = element.Descendants(ns + "stringTable").FirstOrDefault();
                if (stringTable != null)
                {
                    var strings = stringTable.DescendantNodes().OfType<XElement>().ToArray();
                    var table = new Dictionary<string, string>(strings.Length);
                    Array.ForEach(strings, node => { try { table.Add((string)node.Attribute("id"), (string)node.Attribute("value")); } catch { } });
                    manifest.StringTable = table;
                }

                var providerElement = element.Descendants(ns + "provider").First();
                manifest.ProviderName = (string)providerElement.Attribute("name");
                manifest.ProviderSymbol = (string)providerElement.Attribute("symbol");
                manifest.ProviderGuid = Guid.Parse((string)providerElement.Attribute("guid"));

                var events = from node in element.Descendants(ns + "event")
                             let level = GetString(node.Attribute("level"))
                             select new EtwEvent
                             {
                                 Value = (int)node.Attribute("value"),
                                 Symbol = (string)node.Attribute("symbol"),
                                 Level = level.Substring(level.IndexOf(':') + 1),
                                 Opcode = GetString(node.Attribute("opcode")),
                                 Version = (int)node.Attribute("version"),
                                 Template = (string)node.Attribute("template"),
                                 Keyword = (string)node.Attribute("keywords"),
                                 Task = (string)node.Attribute("task")
                             };

                manifest.Events = events.ToArray();

                var keywords = element.Descendants(ns + "keyword").Select(node => new EtwKeyword
                {
                    Name = (string)node.Attribute("name"),
                    Mask = ulong.Parse(((string)node.Attribute("mask")).Substring(2), System.Globalization.NumberStyles.HexNumber),
                    Message = GetMessageString(manifest, (string)node.Attribute("message"))
                });

                manifest.Keywords = keywords.ToArray();

                var templates = element.Descendants(ns + "template").Select(node => new EtwTemplate(node));
                manifest.Templates = templates.ToArray();

                var tasks = element.Descendants(ns + "task").Select(node => new EtwTask(node, manifest));
                manifest.Tasks = tasks.ToArray();

                return manifest;
            }
            catch (Exception ex)
            {
                throw new ApplicationException("Failed to parse manifest XML", ex);
            }
        }

        private static string GetString(XAttribute attribute)
        {
            if (attribute == null)
                return string.Empty;
            var value = (string)attribute;
            return value.Substring(value.IndexOf(':') + 1);
        }

        private static string GetMessageString(EtwManifest manifest, string message)
        {
            if (message.StartsWith("$"))
            {
                message = message.Substring(9, message.Length - 10);
                return manifest.GetString(message);
            }
            return message;
        }

        public static EtwManifest Parse(string xml)
        {
            return Parse(XElement.Parse(xml));
        }

        /// <summary>Reads a qualifier that may be declared as a scalar or an array.</summary>
        private static string[] ToStringArray(object value)
        {
            if (value is string scalar)
                return new[] { scalar };

            if (value is Array array)
            {
                var values = new List<string>(array.Length);
                foreach (var element in array)
                    values.Add(element?.ToString() ?? string.Empty);
                return values.ToArray();
            }

            return null;
        }

        /// <summary>
        /// The versioned spelling of an event name, as a manifest writes it:
        /// "Process_Start" at version 0, "Process_Start_V4" at version 4.
        /// Version 0 takes no suffix.
        /// </summary>
        private static string VersionedName(string eventName, int version)
        {
            return version == 0 ? eventName : $"{eventName}_V{version}";
        }

        /// <summary>"Process_V2" -> "Process". Leaves names without the suffix alone.</summary>
        private static string StripVersionSuffix(string name)
        {
            if (string.IsNullOrEmpty(name))
                return name;
            var match = VersionSuffix.Match(name);
            return match.Success ? match.Groups["Name"].Value : name;
        }

        /// <summary>
        /// The name for one opcode of an event class.
        /// EventTypeName is positional against EventType, but the two are not always the same
        /// length, so the index is clamped rather than assumed.
        /// </summary>
        private static string OpcodeName(string[] eventTypeNames, int index, int opcode, string templateClass)
        {
            // A class that names its opcodes at all keeps naming them. FileOperation is the
            // only class here that runs short - 43 EventTypes against the single name
            // "FileTrace" - because its EventTypes are IRP major function codes (0
            // IRP_MJ_CREATE .. 27 IRP_MJ_MAXIMUM_FUNCTION, then the filter manager range
            // 236-255), not ETW opcodes. Falling through to the generic table there would
            // publish IRP_MJ_CLOSE as "End", so clamp to what the MOF actually declares.
            if (eventTypeNames != null && eventTypeNames.Length > 0)
            {
                var declared = eventTypeNames[Math.Min(index, eventTypeNames.Length - 1)];
                if (!string.IsNullOrEmpty(declared))
                    return declared;
            }

            // Nothing declared - only the Dedup and Vss WPP tracing classes - so the generic
            // meaning of the opcode beats repeating the class name.
            if (StandardOpcodeNames.TryGetValue(opcode, out var standard))
                return standard;

            return StripVersionSuffix(templateClass);
        }

        /// <summary>Every EventTrace subclass, indexed by its Guid class qualifier.</summary>
        private static Dictionary<Guid, ManagementClass> ProviderClasses()
        {
            if (_providerClasses != null)
                return _providerClasses;

            // afaik you can't query for qualifiers...just classes and properties.  :-/
            // so we read the Guid qualifier of every EventTrace class, once
            var providerClasses = new Dictionary<Guid, ManagementClass>();
            var providerSearcher = new ManagementObjectSearcher("root\\WMI", $"SELECT * FROM meta_class WHERE __superclass = 'EventTrace'", AmendedQualifiers);
            foreach (ManagementClass providerClass in providerSearcher.Get())
            {
                foreach (QualifierData qd in providerClass.Qualifiers)
                {
                    if (qd.Name.ToLower() != "guid")
                        continue;

                    // first class wins, as the linear search this replaces did
                    var guid = new Guid((string)qd.Value);
                    if (!providerClasses.ContainsKey(guid))
                        providerClasses.Add(guid, providerClass);
                    break;
                }
            }

            _providerClasses = providerClasses;
            return _providerClasses;
        }

        /// <summary>
        /// Every descendant of <paramref name="rootClass"/>, indexed by superclass.
        /// </summary>
        /// <remarks>
        /// One WMI round trip for the whole subtree; round trips are what this parser costs,
        /// so resolve the hierarchy from the map rather than querying per class.
        ///
        /// ISA is a hierarchy operator, not a prefix match: `ISA 'HeapTrace'` will not pick up
        /// the similarly named HeapTraceProvider that sits above it. It does return the root
        /// class itself, left here under its own superclass where nothing looks it up.
        /// </remarks>
        private static Dictionary<string, List<ManagementClass>> GetSubtreeBySuperclass(string rootClass)
        {
            var bySuperclass = new Dictionary<string, List<ManagementClass>>(StringComparer.OrdinalIgnoreCase);
            var searcher = new ManagementObjectSearcher("root\\WMI", $"SELECT * FROM meta_class WHERE __this ISA '{rootClass}'", AmendedQualifiers);
            foreach (ManagementClass wmiClass in searcher.Get())
            {
                var superclass = wmiClass["__SUPERCLASS"] as string;
                if (string.IsNullOrEmpty(superclass))
                    continue;
                if (!bySuperclass.TryGetValue(superclass, out var children))
                    bySuperclass[superclass] = children = new List<ManagementClass>();
                children.Add(wmiClass);
            }

            return bySuperclass;
        }

        /// <summary>The direct subclasses of <paramref name="className"/>, or none.</summary>
        private static IEnumerable<ManagementClass> ChildrenOf(Dictionary<string, List<ManagementClass>> subtree, string className)
        {
            return subtree.TryGetValue(className, out var children) ? children : Enumerable.Empty<ManagementClass>();
        }

        public static EtwManifest ParseWmiEventTraceClass(Guid provider)
        {
            // we make a best effort attempt to fit the metadata of this Legacy (MOF) provider into the instrumentation manifest format

            // we need to find the EventTrace class where the Guid class qualifier matches our provider Guid
            if (!ProviderClasses().TryGetValue(provider, out var providerClass))
                throw new ApplicationException($"Provider {provider} has no corresponding EventTrace class in WMI Repository"); // not found

            var manifest = new EtwManifest(string.Empty)
            {
                ProviderGuid = provider,
                ProviderSymbol = (string)providerClass["__CLASS"]
            };

            var events = new SortedDictionary<string, EtwEvent>();
            var templates = new List<EtwTemplate>();
            var stringTable = new Dictionary<string, string>();

            // the provider name is usually in the Description Qualifier for the EventTrace class (but not always?)
            // and the keywords are properties for the EventTrace class
            // but we can already get both of these easily from Microsoft.Diagnostics.Tracing
            manifest.ProviderName = TraceEventProviders.GetProviderName(provider);
            manifest.Keywords = TraceEventProviders.GetProviderKeywords(provider).Select(info => new EtwKeyword
            {
                Name = info.Name,
                Mask = info.Value,
                Message = info.Description
            }).ToArray();

            // event details are in the grandchildren of the top-level (EventTrace) provider class
            // WMI EventTrace children ~ a versioned category grouping
            // WMI EventTrace grandchildren ~ instrumentation manifest templates
            // note - event version can be set on the category and/or the event
            var subtree = GetSubtreeBySuperclass((string)providerClass["__CLASS"]);
            foreach (var categoryVersionClass in ChildrenOf(subtree, (string)providerClass["__CLASS"]))
            {
                var categoryVersion = 0;
                var category = string.Empty;
                var categoryDescription = string.Empty;
                var displayName = string.Empty;
                string[] displayNames = null;
                foreach (QualifierData qd in categoryVersionClass.Qualifiers)
                {
                    if (qd.Value.GetType() == typeof(Int32) && qd.Name.ToLower() == "eventversion")
                        categoryVersion = (Int32)qd.Value;
                    else if (qd.Value.GetType() == typeof(String) && qd.Name.ToLower() == "guid")
                        category = (string)qd.Value;
                    else if (qd.Value.GetType() == typeof(String) && qd.Name.ToLower() == "description")
                        categoryDescription = (string)qd.Value;
                    else if (qd.Value.GetType() == typeof(String) && qd.Name.ToLower() == "displayname")
                        displayName = (string)qd.Value;
                    else if (qd.Name.ToLower() == "displaynames")
                        displayNames = ToStringArray(qd.Value);
                }

                // MSLSA_LookupIsolatedNameInTrustedDomains is the one category that declares
                // the plural DisplayNames{"LookupIsolatedNameInTrustedDomains"} and no
                // DisplayName, so read it rather than falling back to the class name.
                if (string.IsNullOrEmpty(displayName) && displayNames != null && displayNames.Length > 0)
                    displayName = displayNames[0];

                // The task half of an event name. DisplayName is the authoritative one and is
                // what TDH reports - it is "OLEDB" for Bid2Etw_OLEDB_1_Trace, which stripping
                // the class name could never produce. Only 3 of the ~190 categories declare
                // neither form, so the stripped class name is just a backstop.
                var taskName = !string.IsNullOrEmpty(displayName)
                    ? displayName
                    : StripVersionSuffix((string)categoryVersionClass["__CLASS"]);

                foreach (var templateClass in ChildrenOf(subtree, (string)categoryVersionClass["__CLASS"]))
                {
                    // EventTypeName qualifier ~ OpCode. It is an array when the class covers
                    // several opcodes, e.g. Process_V4_TypeGroup1 declares EventType{1, 2, 3,
                    // 4, 39} with EventTypeName{"Start", "End", "DCStart", "DCEnd", "Defunct"},
                    // so it is read positionally below.
                    var template = (string)templateClass["__CLASS"];
                    string[] eventTypeNames = null;
                    var version = categoryVersion;
                    var description = categoryDescription;
                    foreach (QualifierData qd in templateClass.Qualifiers)
                    {
                        if (qd.Value.GetType() == typeof(Int32) && qd.Name.ToLower() == "eventversion")
                            version = (Int32)qd.Value; // override category version with specific event version
                        else if (qd.Name.ToLower() == "eventtypename")
                            eventTypeNames = ToStringArray(qd.Value);
                        else if (qd.Value.GetType() == typeof(String) && qd.Name.ToLower() == "description")
                            description = (string)qd.Value;
                    }
                    if (!string.IsNullOrEmpty(categoryDescription))
                        stringTable.Add(template, categoryDescription);

                    // EventType -> id(s), in declaration order. This list is NOT sorted:
                    // EventTypeName pairs with it by position, so reordering here would
                    // silently attach the wrong name to an opcode. The events dictionary sorts
                    // for output anyway.
                    var ids = new List<Int32>();
                    foreach (QualifierData qd in templateClass.Qualifiers)
                    {
                        if (qd.Name.ToLower() == "eventtype")
                        {
                            if (qd.Value.GetType() == typeof(Int32))
                                ids.Add((Int32)qd.Value);
                            else if (qd.Value.GetType().IsArray)
                            {
                                foreach (var element in (Array)qd.Value)
                                {
                                    if (element.GetType() == typeof(Int32))
                                        ids.Add((Int32)element);
                                }
                            }
                            break;
                        }
                    }

                    // sort by category, id, version
                    var addedIds = new HashSet<Int32>();
                    for (var i = 0; i < ids.Count; i++)
                    {
                        var id = ids[i];
                        // A class that repeats an EventType would otherwise throw out of
                        // events.Add and lose the whole provider. Skipping the repeat is what
                        // the SortedSet used to do; i still tracks the declaration position, so
                        // the EventTypeName pairing is unaffected.
                        if (!addedIds.Add(id))
                            continue;

                        // A WMI class name (Process_V4_TypeGroup1) names a group of opcodes;
                        // task plus opcode names one event - Process_Start, FileIo_MapFile,
                        // OLEDB_TextW.
                        var opcodeName = OpcodeName(eventTypeNames, i, id, template);
                        events.Add($"{category}{id,6}{version,6}",
                            new EtwEvent
                            {
                                Value = id,
                                Symbol = VersionedName($"{taskName}_{opcodeName}", version),
                                Opcode = opcodeName,
                                Version = version,
                                Template = template,
                                // Task and Keyword carry the category Guid and the description
                                // straight into the tsv columns of the same name. EtwExplorer
                                // spends them on Task=unversioned name / Keyword=class name
                                // instead - keep that in mind when syncing the two.
                                Keyword = description,
                                Task = category
                            });
                    }

                    // create a template from the properties
                    var templateData = new SortedDictionary<int, EtwTemplateData>();
                    foreach (PropertyData pd in templateClass.Properties)
                    {
                        foreach (QualifierData qd in pd.Qualifiers)
                        {
                            if (qd.Value.GetType() == typeof(Int32) && qd.Name.ToLower() == "wmidataid")
                            {
                                var id = (int)qd.Value;
                                templateData[id] = new EtwTemplateData
                                {
                                    Name = pd.Name,
                                    Type = pd.Type.ToString()
                                };
                                break;
                            }
                        }
                    }

                    templates.Add(new EtwTemplate(template, templateData.Values.ToArray()));
                }
            }

            manifest.Events = events.Values.ToArray();
            manifest.Templates = templates.ToArray();
            manifest.StringTable = stringTable;

            return manifest;
        }
    }
}
