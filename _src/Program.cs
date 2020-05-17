using System;
using System.IO;
using System.Linq;
using System.Xml;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Win32;

using EtwManifestParsing;  // https://github.com/zodiacon/EtwExplorer/tree/master/EtwManifestParsing
using WinTools;            // https://github.com/lallousx86/WinTools/tree/master/WEPExplorer

namespace DumpRegisteredEtwProviders
{
    class Program
    {
        static void Main()
        {
            /*
             * output all ETW events in a single line 'grep-able' format per provider
             * 
             * Microsoft.Diagnostics.Tracing does the heavy lifting and provides us with a (partial) ETW manifest,
             * but lallousx86's WEPExplorer provides improved metadata for providers that are also 
             * Eventlog Providers (i.e. channel, message template).
             * Unfortunately it it doesn't output event names, so we need to combine both.
             * 
             * This ticket would remove the need for the dependency on WEPExplorer -
             * https://github.com/microsoft/perfview/issues/1067
             *
             * And these two tickets would improve the quality of the generated manifest XML
             * https://github.com/microsoft/perfview/issues/1068
             * https://github.com/microsoft/perfview/issues/1069
             *
             * For convenience, I also use the manifest parsing code from EtwExplorer.
             * And was about to contribute back my MOF parsing code.
             */

            /*
             * you need to separately build WEPExplorer and copy cli.exe to your working directory
             * https://github.com/lallousx86/WinTools/tree/master/WEPExplorer
             */
            var useWEPExplorer = File.Exists(WinTools.Cli.CLI_PATH);
            if (!useWEPExplorer)
            {
                Console.WriteLine($"{Cli.CLI_PATH} from WEPExplorer is missing - Eventlog provider data will be incomplete");
            }

            var outputDir = "output";
            var manifestOutputDir = Path.Combine(outputDir, "manifest");
            var mofOutputDir = Path.Combine(outputDir, "mof");
            var unknownOutputDir = Path.Combine(outputDir, "unknown");
            Directory.CreateDirectory(outputDir);
            Directory.CreateDirectory(manifestOutputDir);
            Directory.CreateDirectory(mofOutputDir);
            Directory.CreateDirectory(unknownOutputDir);

            var product = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName", "").ToString();
            var release = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ReleaseId", "").ToString();
            var build = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "BuildLabEx", "").ToString();
            using (var windowsVersionFile = new StreamWriter(Path.Combine(outputDir, "version.txt")))
            {
                windowsVersionFile.WriteLine($"{product} {release} ({build})");
            }

            foreach (var provider in TraceEventProviders.GetPublishedProviders())
            {
                var name = TraceEventProviders.GetProviderName(provider);

                // use the provider name as the output filename, but...
                // ':' is not a valid filename character - use a dash instead
                // and I just don't like spaces in filenames - use an underscore instead
                var tsvFilename = $"{name}.tsv".Replace(' ', '_').Replace(':', '-');

                bool foundProviderDetails = false;
                EtwManifest manifest = null;

                // is this is manifest-based provider?
                string manifestXML = string.Empty;
                try
                {
                    manifestXML = RegisteredTraceEventParser.GetManifestForRegisteredProvider(provider);

                    using (var tsvFile = new StreamWriter(Path.Combine(manifestOutputDir, tsvFilename)))
                    {
                        // Summary:
                        //     Given a provider GUID that has been registered with the operating system, get
                        //     a string representing the ETW manifest for that provider. Note that this manifest
                        //     is not as rich as the original source manifest because some information is not
                        //     actually compiled into the binary manifest that is registered with the OS.

                        // a few hacky escaping fixes so that we can parse the xml...
                        if (name == "Microsoft-Windows-AppXDeployment-Server")
                        {
                            manifestXML = manifestXML.Replace("\"any\"", "&quot;any&quot;");
                        }
                        if (name == "Microsoft-Windows-GroupPolicy")
                        {
                            manifestXML = manifestXML.Replace("\"No loopback mode\"", "&quot;No loopback mode&quot;");
                            manifestXML = manifestXML.Replace("\"Merge\"", "&quot;Merge&quot;");
                            manifestXML = manifestXML.Replace("\"Replace\"", "&quot;Replace&quot;");
                        }
                        if (name == "Microsoft-Windows-NetworkProvider")
                        {
                            manifestXML = manifestXML.Replace("<Property>", "&lt;Property&gt;");
                            manifestXML = manifestXML.Replace("<Value>", "&lt;Value&gt;");
                            manifestXML = manifestXML.Replace("<Integer>", "&lt;Integer&gt;");
                            manifestXML = manifestXML.Replace("<Quoted String>", "&lt;Quoted String&gt;");
                        }
                        if (name == "Microsoft-Windows-Ntfs")
                        {
                            manifestXML = manifestXML.Replace("\"CHKDSK /SCAN\"", "&quot;CHKDSK /SCAN&quot;");
                            manifestXML = manifestXML.Replace("\"CHKDSK /SPOTFIX\"", "&quot;CHKDSK /SPOTFIX&quot;");
                            manifestXML = manifestXML.Replace("\"CHKDSK /F\"", "&quot;CHKDSK /F&quot;");
                            manifestXML = manifestXML.Replace("\"REPAIR-VOLUME <drive:> -SCAN\"", "&quot;REPAIR-VOLUME &lt;drive:&gt; -SCAN&quot;");
                            manifestXML = manifestXML.Replace("\"REPAIR-VOLUME <drive:>\"", "&quot;REPAIR-VOLUME &lt;drive:&gt;&quot;");
                            manifestXML = manifestXML.Replace("<unknown>", "&lt;unknown&gt;");
                        }

                        manifest = ManifestParser.Parse(manifestXML);

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


                            var Channel = string.Empty;
                            var Message = string.Empty;
                            if (useWEPExplorer)
                            {
                                // add channel and message from WEPExplorer (if available)
                                var xmlNode = WEPExplorer.GetProviderMetadataXml(name);
                                try
                                {
                                    if (xmlNode != null && xmlNode.HasChildNodes)
                                    {
                                        foreach (XmlNode xnEvent in xmlNode.SelectNodes($"/{WEPExplorer.XML_PROVIDERS}/{WEPExplorer.XML_PROVIDER}/{WEPExplorer.XML_EVENT_METADATA}/{WEPExplorer.XML_EVENT}[{WEPExplorer.XML_ID}={evt.Value}][{WEPExplorer.XML_VERSION}={evt.Version}]"))
                                        {
                                            Channel = WEPExplorer.xnGetText(xnEvent, WEPExplorer.XML_CHANNEL);
                                            Message = WEPExplorer.xnGetText(xnEvent, WEPExplorer.XML_MESSAGE).Replace("\r", @"\r").Replace("\n", @"\n");
                                        }
                                    }
                                }
                                catch
                                {
                                    var errorFilename = "ERROR_WEPExplorer.xml";
                                    Console.WriteLine($"WEPExplorer XML PARSE FAILURE - name={name} file={errorFilename}");
                                    using (var errorFile = new StreamWriter(Path.Combine(outputDir, errorFilename)))
                                    {
                                        errorFile.WriteLine(xmlNode.OuterXml);
                                    }
                                }
                            }

                            var etwEvent = $"{name}\t{evt.Value}\t{evt.Version}\t{evt.Symbol}({fields})\t{evt.Opcode}\t{evt.Keyword}\t{evt.Task}\t{evt.Level}\t{Channel}\t{Message}";
                            etwEvent = etwEvent.Replace("&quot;", "\"").Replace("&lt;", "<").Replace("&gt;", ">");
                            tsvFile.WriteLine(etwEvent);
                        }
                    }
                }
                catch (Exception e)
                {
                    if (manifestXML.Length != 0)
                    {
                        var errorFilename = "ERROR_Manifest.xml";
                        Console.WriteLine($"MANIFEST PARSE FAILURE - name={name} size={manifestXML.Length} file={errorFilename}");
                        using (var errorFile = new StreamWriter(Path.Combine(outputDir, errorFilename)))
                        {
                            errorFile.WriteLine(manifestXML);
                        }
                        throw e;
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


                // no manifest and no MOF...
                if (!foundProviderDetails)
                {
                    using (var tsv_file = new StreamWriter(Path.Combine(unknownOutputDir, tsvFilename)))
                    {
                        tsv_file.WriteLine($"provider");
                        tsv_file.WriteLine(name);
                    }
                }
            }

            Console.WriteLine("All done");
        }
    }
}
