using Microsoft.Diagnostics.Tracing.Session;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Xml.Linq;

namespace EtwManifestParsing
{
    public static class ManifestParser
    {
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

        public static EtwManifest ParseWmiEventTraceClass(Guid provider)
        {
            // we make a best effort attempt to fit the metadata of this Legacy (MOF) provider into the instrumentation manifest format

            // we need to find the EventTrace class where the Guid class qualifier matches our provider Guid
            // afaik you can't query for qualifiers...just classes and properties.  :-/
            // so we loop through all of the EventTrace classes and compare
            var providerSearcher = new ManagementObjectSearcher("root\\WMI", $"SELECT * FROM meta_class WHERE __superclass = 'EventTrace'", null);
            ManagementClass providerClass = null;
            foreach (ManagementClass candidateProviderClass in providerSearcher.Get())
            {
                foreach (QualifierData qd in candidateProviderClass.Qualifiers)
                {
                    if (qd.Name.ToLower() == "guid" && new Guid((string)qd.Value) == provider)
                    {
                        providerClass = candidateProviderClass;
                        break; // found
                    }
                }

                if (providerClass != null)
                    break; // found
            }

            if (providerClass == null)
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
            var templateNames = new SortedSet<string>();
            var taskSearcher = new ManagementObjectSearcher("root\\WMI", $"SELECT * FROM meta_class WHERE __superclass = '{providerClass["__CLASS"]}'", null);
            foreach (ManagementClass categoryVersionClass in taskSearcher.Get())
            {
                var categoryVersion = 0;
                var category = string.Empty;
                var categoryDescription = string.Empty;
                var displayName = string.Empty;
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
                }

                var templateSearcher = new ManagementObjectSearcher("root\\WMI", $"SELECT * FROM meta_class WHERE __superclass = '{categoryVersionClass["__CLASS"]}'", null);
                foreach (ManagementClass templateClass in templateSearcher.Get())
                {
                    // EventTypeName qualifier ~ OpCode
                    var template = (string)templateClass["__CLASS"];
                    var eventType = string.Empty;
                    var version = categoryVersion;
                    var description = categoryDescription;
                    foreach (QualifierData qd in templateClass.Qualifiers)
                    {
                        if (qd.Value.GetType() == typeof(Int32) && qd.Name.ToLower() == "eventversion")
                            version = (Int32)qd.Value; // override category version with specific event version
                        else if (qd.Value.GetType() == typeof(String) && qd.Name.ToLower() == "eventtypename")
                            eventType = (string)qd.Value;
                        else if (qd.Value.GetType() == typeof(String) && qd.Name.ToLower() == "description")
                            description = (string)qd.Value;
                    }
                    if (!string.IsNullOrEmpty(categoryDescription))
                        stringTable.Add(template, categoryDescription);

                    // EventType -> id(s)
                    var ids = new SortedSet<Int32>();
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
                    foreach (var id in ids)
                    {
                        events.Add($"{category}{id,6}{version,6}",
                            new EtwEvent
                            {
                                Value = id,
                                Symbol = template,
                                Opcode = eventType,
                                Version = version,
                                Template = template,
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
