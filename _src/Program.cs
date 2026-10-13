using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Win32;

using EtwManifestParsing;  // https://github.com/zodiacon/EtwExplorer/tree/master/EtwManifestParsing

namespace DumpRegisteredEtwProviders
{
    class Program
    {
        static void Main()
        {
            /*
             * output all ETW events in a single line 'grep-able' format per provider
             * 
             * TdhManifestReader reads each registered provider's events straight from TDH (this used to be
             * TraceEvent's GetManifestForRegisteredProvider - see TdhManifestReader for why it isn't), and
             * EventLogMetadata adds what only the Event Log API (wevtapi) has: each event's channel and
             * message template - and all of the events of providers whose manifest TDH cannot decode.
             *
             * For convenience, I also use the manifest parsing code from EtwExplorer.
             * And was about to contribute back my MOF parsing code.
             */

            var outputDir = "output";
            var manifestOutputDir = Path.Combine(outputDir, "manifest");
            var mofOutputDir = Path.Combine(outputDir, "mof");
            var unknownOutputDir = Path.Combine(outputDir, "unknown");
            Directory.CreateDirectory(outputDir);
            Directory.CreateDirectory(manifestOutputDir);
            Directory.CreateDirectory(mofOutputDir);
            Directory.CreateDirectory(unknownOutputDir);

            var cvKey = @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion";
            var product = Registry.GetValue(cvKey, "ProductName", "").ToString();
            // ReleaseId froze at "2009"; DisplayVersion carries the real release (e.g. "22H2").
            // Fall back to ReleaseId for older builds that predate DisplayVersion.
            var release = Registry.GetValue(cvKey, "DisplayVersion", "").ToString();
            if (string.IsNullOrEmpty(release)) { release = Registry.GetValue(cvKey, "ReleaseId", "").ToString(); }
            var build = Registry.GetValue(cvKey, "BuildLabEx", "").ToString();
            // ProductName stays "Windows 10" on Windows 11 - correct it for builds >= 22000.
            var currentBuild = Registry.GetValue(cvKey, "CurrentBuildNumber", "0").ToString();
            if (int.TryParse(currentBuild, out var buildNumber) && buildNumber >= 22000)
            {
                product = product.Replace("Windows 10", "Windows 11");
            }
            using (var windowsVersionFile = new StreamWriter(Path.Combine(outputDir, "version.txt")))
            {
                windowsVersionFile.WriteLine($"{product} {release} ({build})");
            }

            foreach (var entry in TdhManifestReader.GetPublishedProviders())
            {
                var provider = entry.Key;
                var name = entry.Value;

                // use the provider name as the output filename, but...
                // ':' is not a valid filename character - use a dash instead
                // and I just don't like spaces in filenames - use an underscore instead
                var tsvFilename = $"{name}.tsv".Replace(' ', '_').Replace(':', '-');

                bool foundProviderDetails = false;
                EtwManifest manifest = null;

                // what the Event Log API says about the provider's events - none if it isn't a publisher
                var eventLogEvents = new List<ReconstructedEvent>();
                try
                {
                    eventLogEvents = EventLogMetadata.GetEvents(name);
                }
                catch (Exception e)
                {
                    Console.WriteLine($"EVENTLOG METADATA FAILURE - name={name} error={e.Message}");
                }

                // is this is manifest-based provider?
                try
                {
                    manifest = TdhManifestReader.GetManifest(provider);
                }
                catch (ApplicationException) { }       // TDH has no events for it
                catch (InvalidOperationException) { }  // TDH listed keywords but could not return them

                if (manifest != null)
                {
                    // channel and message by the id and version the Event Log API knows each event by
                    var eventLogDetails = new Dictionary<string, ReconstructedEvent>();
                    foreach (var eventLogEvent in eventLogEvents)
                        eventLogDetails[$"{eventLogEvent.EventLogId}/{eventLogEvent.Version}"] = eventLogEvent;

                    using (var tsvFile = new StreamWriter(Path.Combine(manifestOutputDir, tsvFilename)))
                    {
                        foundProviderDetails = true;

                        tsvFile.WriteLine($"provider\tevent_id\tversion\tevent(fields)\topcode\tkeywords\ttask\tlevel\tevtlog_channel\tevtlog_message");
                        foreach (var evt in manifest.Events)
                        {
                            var fields = string.Empty;
                            try
                            {
                                foreach (var param in manifest.Templates.First(t => t.Id == evt.Template).Items)
                                {
                                    if (fields != string.Empty)
                                    {
                                        fields += ", ";
                                    }
                                    fields += $"{param.Type} {param.Name}";
                                }
                            }
                            catch (InvalidOperationException) { } // no fields

                            eventLogDetails.TryGetValue($"{evt.EventLogId}/{evt.Version}", out var details);
                            tsvFile.WriteLine($"{name}\t{evt.Value}\t{evt.Version}\t{evt.Symbol}({fields})\t{evt.Opcode}\t{evt.Keyword}\t{evt.Task}\t{evt.Level}\t{details?.Channel}\t{details?.Message}");
                        }
                    }
                }


                // is this a legacy (MOF-based) provider
                manifest = null;
                try
                {
                    manifest = ManifestParser.ParseWmiEventTraceClass(provider);
                }
                catch (ApplicationException) { }

                if (manifest != null)
                {

                    foundProviderDetails = true;
                    using (var tsv_file = new StreamWriter(Path.Combine(mofOutputDir, tsvFilename)))
                    {
                        tsv_file.WriteLine($"provider\tcategory\tevent_id\tversion\tevent(fields)\tevent_type\tdescription");
                        foreach (var evt in manifest.Events)
                        {
                            var fields = string.Empty;
                            try
                            {
                                foreach (var param in manifest.Templates.First(t => t.Id == evt.Template).Items)
                                {
                                    if (!string.IsNullOrEmpty(fields))
                                    {
                                        fields += ", ";
                                    }
                                    fields += $"{param.Type} {param.Name}";
                                }
                            }
                            catch (InvalidOperationException) { } // no fields

                            var etwEvent = $"{name}\t{evt.Task}\t{evt.Value}\t{evt.Version}\t{evt.Symbol}({fields})\t{evt.Opcode}\t{evt.Keyword}";
                            etwEvent = etwEvent.Replace("&quot;", "\"").Replace("&lt;", "<").Replace("&gt;", ">");
                            tsv_file.WriteLine(etwEvent);
                        }
                    }
                }


                // no manifest TDH can decode and no MOF...
                if (!foundProviderDetails)
                {
                    if (eventLogEvents.Count != 0)
                    {
                        // ...but the Event Log API reads the same manifest: TDH failed on something else, such as
                        // a missing .mui satellite (unknown/README.md). These are complete manifest providers.
                        using (var tsv_file = new StreamWriter(Path.Combine(manifestOutputDir, tsvFilename)))
                        {
                            tsv_file.WriteLine($"provider\tevent_id\tversion\tevent(fields)\topcode\tkeywords\ttask\tlevel\tevtlog_channel\tevtlog_message");
                            foreach (var evt in eventLogEvents)
                            {
                                tsv_file.WriteLine($"{name}\t{evt.Id}\t{evt.Version}\t{evt.Signature}\t{evt.Opcode}\t{evt.Keywords}\t{evt.Task}\t{evt.Level}\t{evt.Channel}\t{evt.Message}");
                            }
                        }
                    }
                    else
                    {
                        // TDH's reason, and the manifest it was registered with
                        var tdhStatus = EventLogMetadata.DescribeStatus(EventLogMetadata.TdhStatus(provider));
                        using (var tsv_file = new StreamWriter(Path.Combine(unknownOutputDir, tsvFilename)))
                        {
                            // keep the provider name in the first row - docs/build_data.py reads it from there
                            tsv_file.WriteLine($"provider\ttdh_status\tresource_file");
                            tsv_file.WriteLine($"{name}\t{tdhStatus}\t{EventLogMetadata.RegisteredResourceFile(provider)}");
                        }
                    }
                }
            }

            Console.WriteLine("All done");
        }
    }
}
