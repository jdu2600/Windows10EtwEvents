/* ----------------------------------------------------------------------------- 
* Windows Events Providers Explorer / GUI
* Copyright (c) Elias Bachaalany <lallousz-x86@yahoo.com>
* All rights reserved.
* 
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
* 1. Redistributions of source code must retain the above copyright
*    notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
*    notice, this list of conditions and the following disclaimer in the
*    documentation and/or other materials provided with the distribution.
* 
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
* OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
* LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
* OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
* SUCH DAMAGE.
* ----------------------------------------------------------------------------- 
*
*
* 01/19/2016 - Initial version
* 01/20/2016 - Added "File/Clear cache"
* 01/26/2016 - Added Template fields filter
*            - Implemented Message content filter
*            - Implemented "Copy provider name", "IDs", and "IDs as case" functionalities
* 01/27/2016 - Added "Delete" context menu to the provider metadata list. This will help filtering the output.
*            - Added keyboard shortcuts
*            - More filter options for the provider template fields
* 03/16/2016 - Bumped to version 1.2
*            - Added name/guid provider filter
*            - Added Copy provider GUID
* 03/17/2016 - Format Keyword flag as hexadecimal
* 03/20/2016 - v1.2.1
*            - Added Keywords listview / "Copy Flags"
*
TODO
------

- Start using FluentLib.NET instead
- Investigate how to improve the cli utility, I feel it is blocked / has bugs or missing information.

*/
using System;
using System.Collections.Generic;
using System.IO;
using System.Xml;

namespace WinTools
{
    public class WEPExplorer
    {
        private static string ProvidersMetadataFolder = "Providers";

        #region XML consts
        public const string XML_CHANNEL = "Channel";
        public const string XML_CHANNELS = "Channels";
        public const string XML_EVENT_METADATA = "EventMetadata";
        public const string XML_GUID = "Guid";
        public const string XML_HELPLINK = "HelpLink";
        public const string XML_ID = "Id";
        public const string XML_EVENT = "Event";
        public const string XML_IMPORTED = "Imported";
        public const string XML_INDEX = "Index";
        public const string XML_KEYWORD = "Keyword";
        public const string XML_KEYWORDS = "Keywords";
        public const string XML_LEVEL = "Level";
        public const string XML_LEVELS = "Levels";
        public const string XML_MESSAGE = "Message";
        public const string XML_MESSAGEFILEPATH = "MessageFilePath";
        public const string XML_METADATA = "Metadata";
        public const string XML_NAME = "Name";
        public const string XML_OPCODE = "Opcode";
        public const string XML_OPCODES = "Opcodes";
        public const string XML_PARAMETERFILEPATH = "ParameterFilePath";
        public const string XML_PATH = "Path";
        public const string XML_PROVIDER = "Provider";
        public const string XML_PROVIDERS = "Providers";
        public const string XML_PUBLISHER_MESSAGE = "PublisherMessage";
        public const string XML_RESOURCEFILEPATH = "ResourceFilePath";
        public const string XML_TASK = "Task";
        public const string XML_TASKS = "Tasks";
        public const string XML_TEMPLATE = "Template";
        public const string XML_VALUE = "Value";
        public const string XML_VERSION = "Version";
        #endregion

        private static string GetProviderMetadataFile(string ProviderName)
        {
            return Path.Combine(ProvidersMetadataFolder, ProviderName + ".xml");
        }

        public static XmlNode GetProviderMetadataXml(string ProviderName)
        {
            string ProviderMetadataFileName = GetProviderMetadataFile(ProviderName);

            if (!File.Exists(ProviderMetadataFileName))
            {
                if (!Cli.GetProviderMetadata(ProviderName, ProviderMetadataFileName))
                    return null;
            }

            try
            {
                XmlDocument xd = new XmlDocument();
                xd.Load(ProviderMetadataFileName);

                return xd.DocumentElement;
            }
            catch (Exception)
            {
                return null;
            }
        }

        public static string xnGetText(XmlNode xnNode, string NodeName)
        {
            var xn = xnNode.SelectSingleNode(NodeName);
            if (xn == null)
                return string.Empty;
            else
                return xn.InnerText;
        }


        public static string[] GetProviderTemplateFields(string Template)
        {
            Template = Template.Trim();
            if (!string.IsNullOrEmpty(Template))
            {
                try
                {
                    XmlDocument xd = new XmlDocument();
                    xd.LoadXml(Template);

                    List<string> aFields = new List<string>();
                    foreach (XmlNode xnField in xd.DocumentElement.SelectNodes("*"))
                        aFields.Add((xnField.Name == "struct" ? "s:" : "") + xnField.Attributes["name"].Value);
                    
                    return aFields.ToArray();
                }
                catch
                {
                }
            }
            return new string[] { };
        }
    }
}