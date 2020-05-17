using System.Diagnostics;
using System.IO;

/* ----------------------------------------------------------------------------- 
* Copyright (c) Elias Bachaalany <lallousz-x86@yahoo.com>
* All rights reserved.
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
*/
namespace WinTools
{
    public static class Utils
    {
        public static string GetCurrentAsmDirectory()
        {
            return Path.GetDirectoryName((new FileInfo(System.Reflection.Assembly.GetExecutingAssembly().Location)).FullName);
        }
    }

    public static class Cli
    {
        public const string CLI_PATH = @"cli.exe";

        public static bool GetProviders(string Outfile)
        {
            Process p = new Process();
            p.StartInfo = new ProcessStartInfo()
            {
                Arguments = "/out \"" + Outfile + "\"",
                FileName = CLI_PATH,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            p.Start();
            p.WaitForExit();
            return p.ExitCode == 0;
        }

        public static bool GetProviderMetadata(
            string ProviderName,
            string ProvidersFileName)
        {
            Process p = new Process();
            p.StartInfo = new ProcessStartInfo()
            {
                Arguments = "/meta /eventmeta /name \"" + ProviderName + "\" /out \"" + ProvidersFileName + "\"",
                FileName = CLI_PATH,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            p.Start();
            p.WaitForExit();
            return p.ExitCode == 0;
        }
    }
}
