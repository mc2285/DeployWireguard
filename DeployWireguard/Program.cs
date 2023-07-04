using IniParser.Exceptions;
using IniParser.Model;
using IniParser.Parser;
using System;
using System.Diagnostics;
using System.IO;

namespace DeployWireguard
{
    internal class Program
    {
        public const string description =

@"
This is a part of an MDT task sequence that deploys Wireguard to a Windows 10 machine.

It performs the following actions (MSI is installed in a previous step):
    1. Grab the config file from either the default path or the one provided via interactive prompt
    2. Move the config file into the Wireguard Configurations directory
    3. Install the tunnel service from the resulting encrypted DPAPI blob

The exit code is 0 on success, 1 on failure and 2 on help request.

There are no command line arguments, all input is provided via interactive prompts.
No input is required if the config file is in the default location being $USERPROFILE\Desktop\cgof-vpn.conf
";

        internal const string defaultAllowedIPs = "192.168.1.0/24";

        private static void Exit(int code)
        {
            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
            Environment.Exit(code);
        }

        static void Main(string[] args)
        {
            // Respond to desperate help requests
            if (args.Length > 0)
            {
                if (args[0] == "-h" || args[0] == "--help" || args[0] == "/?")
                {
                    Console.WriteLine(description);
                    Environment.Exit(2);
                }
            }

            string _configPath = @"WireGuard\Data\Configurations\";
            string _configName = @"cgof-vpn.conf";
            string _resultingConfigNane = @"cgof-vpn.conf.dpapi";
            string _rawConfigPath = @"Desktop\";


            // Query environment variables for the location of ProgramFiles
            string _envProgramFiles;
            string _envUserprofile;

            _envProgramFiles = Environment.GetEnvironmentVariable("PROGRAMFILES");
            if (_envProgramFiles == null)
            {
                Console.WriteLine("PROGRAMFILES environment variable not found.");
                Exit(1);
            }
            else
            {
                _configPath = Path.Combine(_envProgramFiles, _configPath);
            }

            // Query environment variables for the location of the user's home directory
            _envUserprofile = Environment.GetEnvironmentVariable("USERPROFILE");
            if (_envUserprofile == null)
            {
                Console.WriteLine("USERPROFILE environment variable not found.");
                Exit(1);
            }
            else
            {
                _rawConfigPath = Path.Combine(_envUserprofile, _rawConfigPath);
            }

            // Build target, source and resulting paths
            string sourcePath = Path.Combine(_rawConfigPath, _configName);
            string targetPath = Path.Combine(_configPath, _configName);
            string resultingPath = Path.Combine(_configPath, _resultingConfigNane);

            if (File.Exists(targetPath))
            {
                Console.WriteLine("Config file already exists in the target location: {0}", targetPath);
                Exit(1);
            }
            if (File.Exists(resultingPath))
            {
                Console.WriteLine("File exists: {0}. Tunnel possibly already deployed.", resultingPath);
            }

            // Check for access permissions to create a file at targetPath
            try
            {
                File.Create(targetPath).Close();
                File.Delete(targetPath);
            }
            catch (Exception e)
            {
                Console.WriteLine("Access to the target path denied: {0}", e.Message);
                Exit(1);
            }

            // Block until a satisfactory config file is provided or the program is terminated
            string _tempInput;
            string _fallbackInput = sourcePath;
            while (!File.Exists(sourcePath))
            {
                Console.Write("Config file path: ");
                _tempInput = Console.ReadLine();
                sourcePath = (_tempInput == "") ? _fallbackInput : _tempInput;
            }

            // Open the config file and read it as an array of strings
            // Exit if the file is empty or cannot be read
            string configLines = "";
            try
            {
                configLines = File.ReadAllText(sourcePath);
                if (!configLines.Contains("\n"))
                {
                    Console.WriteLine("Config file is empty.");
                    Exit(1);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("Error reading config file: {0}", e.Message);
                Exit(1);
            }

            // Parse the config file as an INI file, check for errors and presence of required sections
            var parser = new IniDataParser();
            IniData configData = null;
            try
            {
                configData = parser.Parse(configLines);
            }
            catch (ParsingException e)
            {
                Console.WriteLine("Error parsing config file: {0}", e.Message);
                Exit(1);
            }
            if (!configData.Sections.ContainsSection("Interface"))
            {
                Console.WriteLine("Config file does not contain the required [Interface] section.");
                Exit(1);
            }
            if (!configData.Sections.ContainsSection("Peer"))
            {
                Console.WriteLine("Config file does not contain the required [Peer] section.");
                Exit(1);
            }

            // Replace AllowedIPs with required values
            configData["Peer"]["AllowedIPs"] = defaultAllowedIPs;

            // Write the resulting config file to the target location
            try
            {
                File.WriteAllText(sourcePath, configData.ToString());
            }
            catch (Exception e)
            {
                Console.WriteLine("Error writing config file: {0}", e.Message);
                Exit(1);
            }

            // Move the config file to the Wireguard Configurations directory
            try
            {
                File.Move(sourcePath, targetPath);
            }
            catch (Exception e)
            {
                Console.WriteLine("Error moving config file: {0}", e.Message);
                Exit(1);
            }

            // Wait until the wireguard service has processed the config file
            Console.WriteLine();
            Console.Write("Waiting...");
            while (!File.Exists(resultingPath))
            {
                System.Threading.Thread.Sleep(300);
                Console.Write(".");
            }
            Console.WriteLine();

            // Locate the Wireguard control utility
            string _wgExePath = Path.Combine(_envProgramFiles, @"WireGuard\wireguard.exe");
            if (!File.Exists(_wgExePath))
            {
                Console.WriteLine("Wireguard control utility not found at: {0}", _wgExePath);
                Exit(1);
            }

            // Call the command line utility to install the tunnel service
            string _args = "/installtunnelservice \"" + resultingPath + "\"";
            ProcessStartInfo _wgExeInfo = new ProcessStartInfo(_wgExePath, _args)
            {
                LoadUserProfile = true,
                ErrorDialog = false,
                UseShellExecute = true
            };
            Process _wgExeProcess = null;
            try
            {
                _wgExeProcess = Process.Start(_wgExeInfo);
                _wgExeProcess.WaitForExit();
            }
            catch (Exception e)
            {
                Console.WriteLine("Error calling wireguard.exe: {0}", e.Message);
                Exit(1);
            }
            
            // Check for exit code and exit the app
            if (_wgExeProcess.ExitCode == 0)
            {
                Console.WriteLine("Tunnel successfully deployed.");
                Environment.Exit(0);
            }
            else
            {
                Console.WriteLine("Error deploying tunnel. Exit code: {0}", _wgExeProcess.ExitCode);
                Exit(1);    
            }
        }
    }
}
