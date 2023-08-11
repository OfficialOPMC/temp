using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace UWP_YT
{
    class Program
    {
        private static void ProgressChanged(object sender, DownloadProgressChangedEventArgs e)
        {
            Console.WriteLine("Downloading Roblox: " + e.ProgressPercentage + "%");
        }

        private static async Task DownloadFileAsync(string url, string filename)
        {
            try
            {
                using (var webClient = new WebClient())
                {
                    webClient.DownloadProgressChanged += ProgressChanged;
                    await webClient.DownloadFileTaskAsync(new Uri(url), filename);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Failed to download the MSIXBundle: " + ex.Message);
            }
        }

        private static void UninstallRoblox()
        {
            try
            {
                string powershellCommand = "Get-AppxPackage -Name ROBLOXCORPORATION.ROBLOX | Remove-AppxPackage";

                ProcessStartInfo startInfo = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -ExecutionPolicy unrestricted -Command \"{powershellCommand}\"",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    Verb = "runas"
                };

                Process process = Process.Start(startInfo);
                process.WaitForExit();

                if (process.ExitCode == 0)
                {
                    Console.WriteLine("Roblox uninstalled successfully.");
                }
                else
                {
                    Console.WriteLine("Failed to uninstall Roblox.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Failed to uninstall Roblox: " + ex.Message);
            }
        }
        [DllImport("shell32.dll")]
        private static extern void SHChangeNotify(int eventId, int flags, IntPtr item1, IntPtr item2);

        private static void PinToTaskbar(string shortcutPath)
        {
            try
            {
                string taskbarFolderPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + @"\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar";
                string pinnedShortcutPath = Path.Combine(taskbarFolderPath, Path.GetFileName(shortcutPath));

                File.Copy(shortcutPath, pinnedShortcutPath, true);
                SHChangeNotify(0x8000000, 0x1000, IntPtr.Zero, IntPtr.Zero);
                Console.WriteLine("Roblox pinned to taskbar successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Failed to pin Roblox to taskbar: " + ex.Message);
            }
        }

        private static void CreateShortcut(string targetPath, string shortcutPath)
        {
            try
            {
                using (StreamWriter writer = new StreamWriter(shortcutPath))
                {
                    writer.WriteLine("[InternetShortcut]");
                    writer.WriteLine("URL=file:///" + targetPath.Replace('\\', '/'));
                    writer.WriteLine("IconIndex=0");
                    writer.WriteLine("IconFile=" + targetPath.Replace('\\', '/'));
                    writer.Flush();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Failed to create shortcut: " + ex.Message);
            }
        }
        private static bool IsRobloxInstalled(string version, string path)
        {
            string robloxVersionPath = Path.Combine(path, $"ROBLOXCORPORATION.ROBLOX_{version}_x86__55nm5eh3cm0pr");
            return Directory.Exists(robloxVersionPath);
        }
        static void Main(string[] args)
        {
            string robloxVersion = "2.582.384.0";
            string robloxPath = @"C:\Program Files\WindowsApps";
            if (IsRobloxInstalled(robloxVersion, robloxPath))
            {
                Console.WriteLine($"Roblox version {robloxVersion} already installed at {robloxPath}.");
                Console.ReadLine();
                return;
            }

            string msixBundlePath = "Roblox.Msixbundle";

            UninstallRoblox();

            string downloadUrl = "https://cdn.discordapp.com/attachments/1126177245703176212/1128323308824309801/ROBLOXCORPORATION.ROBLOX_2.582.384.0_neutral__55nm5eh3cm0pr.Msixbundle";
            string fileName = "Roblox.Msixbundle";
            try
            {
                Console.WriteLine("Downloading Roblox...");
                if (!File.Exists(fileName))
                {
                    DownloadFileAsync(downloadUrl, fileName).Wait();
                }
                Console.WriteLine("Download completed.");
                
            }
            catch (Exception ex)
            {
                Console.WriteLine("Failed to download the MSIXBundle: " + ex.Message);
                return;
            }

            try
            {
                string powershellCommand = $"Add-AppxPackage \"{msixBundlePath}\"";

                ProcessStartInfo startInfo = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -ExecutionPolicy unrestricted -Command \"{powershellCommand}\"",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    Verb = "runas" 
                };

                Process process = Process.Start(startInfo);
                process.WaitForExit();

                if (process.ExitCode == 0)
                {
                    string robloxExePath = @"C:\Program Files\WindowsApps\ROBLOXCORPORATION.ROBLOX_*\Windows10Universal.exe";
                    string shortcutPath = Path.Combine(Path.GetTempPath(), "Roblox.lnk");
                    CreateShortcut(robloxExePath, shortcutPath);
                    PinToTaskbar(shortcutPath);
                    Console.WriteLine("Roblox reinstalled successfully.");
                }
                else
                {
                    Console.WriteLine("Failed to reinstall Roblox.");
                }

                Console.ReadLine();

            }
            catch (Exception ex)
            {
                Console.WriteLine("Failed to reinstall Roblox: " + ex.Message);
            }

            Console.ReadLine();

        }

        [ComImport]
        [Guid("F935DC23-1CF0-11D0-ADB9-00C04FD58A0B")]
        internal class WshShell { }

        [ComImport]
        [Guid("F935DC21-1CF0-11D0-ADB9-00C04FD58A0B")]
        [InterfaceType(ComInterfaceType.InterfaceIsIDispatch)]
        internal interface IWshShortcut
        {
            string FullName { get; set; }
            string Arguments { get; set; }
            string Description { get; set; }
            string Hotkey { get; set; }
            string IconLocation { get; set; }
            string RelativePath { get; set; }
            string TargetPath { get; set; }
            int WindowStyle { get; set; }
            string WorkingDirectory { get; set; }

            void Load(string path);
            void Save();
        }
    }
}
