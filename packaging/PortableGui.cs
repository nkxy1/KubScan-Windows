using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace KubScan;

internal static class PortableGui
{
    private const string GuiExecutable = "KubScan.WinUI.exe";

    [DllImport("kernel32.dll")]
    private static extern bool AttachConsole(uint processId);

    [DllImport("kernel32.dll")]
    private static extern bool AllocConsole();

    [DllImport("kernel32.dll")]
    private static extern bool FreeConsole();

    [DllImport("kernel32.dll")]
    private static extern uint GetConsoleProcessList(out uint processId, uint processCount);

    [DllImport("kernel32.dll")]
    private static extern bool GetConsoleMode(IntPtr handle, out uint mode);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetStdHandle(int handle);

    internal static bool HasInteractiveParentConsole()
    {
        // An older Windows build can allocate a fresh console for an Explorer
        // launch. Only a shared console indicates an interactive shell launch.
        uint processes = GetConsoleProcessList(out _, 1);
        if (processes == 0 && AttachConsole(uint.MaxValue))
            processes = GetConsoleProcessList(out _, 1);
        return processes > 1
            && GetConsoleMode(GetStdHandle(-10), out _)
            && GetConsoleMode(GetStdHandle(-11), out _);
    }

    internal static void ConnectConsole()
    {
        // Keep inherited pipes and redirected output intact when invoked by scripts.
        var output = GetStdHandle(-11);
        if (output != IntPtr.Zero && output != new IntPtr(-1)) return;
        if (!AttachConsole(uint.MaxValue) && Environment.UserInteractive) AllocConsole();
    }

    internal static bool CanLaunch()
    {
        if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, 17763) || !Environment.UserInteractive)
            return false;

        var installation = Registry.GetValue(
            @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "InstallationType", null) as string;
        return installation == "Client" || installation == "Server";
    }

    internal static int Run()
    {
        FreeConsole();
        var assembly = typeof(PortableGui).Assembly;
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "KubScan", "Portable");
        var cache = Path.Combine(root, assembly.ManifestModule.ModuleVersionId.ToString("N"));
        var executable = Path.Combine(cache, GuiExecutable);
        if (!File.Exists(executable))
        {
            var staging = Path.Combine(root, Guid.NewGuid().ToString("N") + ".tmp");
            Directory.CreateDirectory(staging);
            try
            {
                using var progress = new ExtractionProgress();
                using var stream = assembly.GetManifestResourceStream("KubScan.WinUI.zip")
                    ?? throw new InvalidDataException("Missing bundled WinUI files.");
                using var archive = new ZipArchive(stream, ZipArchiveMode.Read);
                ExtractArchive(archive, staging, progress);
                if (!File.Exists(Path.Combine(staging, GuiExecutable)))
                    throw new InvalidDataException("Missing bundled WinUI executable.");
                // Publish only a complete extraction. Another launch may finish first.
                try { Directory.Move(staging, cache); }
                catch (IOException) when (File.Exists(executable)) { }
            }
            catch (OperationCanceledException) { return 0; }
            finally
            {
                if (Directory.Exists(staging)) Directory.Delete(staging, true);
            }
        }

        using var gui = Process.Start(new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = cache
        });
        gui.WaitForExit();
        return gui.ExitCode;
    }

    private static void ExtractArchive(ZipArchive archive, string staging, ExtractionProgress progress)
    {
        long total = 0;
        foreach (var entry in archive.Entries) total = checked(total + entry.Length);
        long completed = 0;
        var buffer = new byte[128 * 1024];
        var root = Path.GetFullPath(staging) + Path.DirectorySeparatorChar;
        foreach (var entry in archive.Entries)
        {
            var destination = Path.GetFullPath(Path.Combine(root, entry.FullName));
            // Preserve ExtractToDirectory's protection against ZIP path traversal.
            if (!destination.StartsWith(root, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Bundled file is outside the extraction directory.");
            progress.Report(completed, total, entry.Name);
            if (entry.Name.Length == 0)
            {
                Directory.CreateDirectory(destination);
                continue;
            }
            Directory.CreateDirectory(Path.GetDirectoryName(destination));
            using var source = entry.Open();
            using var output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            int read;
            while ((read = source.Read(buffer, 0, buffer.Length)) != 0)
            {
                output.Write(buffer, 0, read);
                completed += read;
                progress.Report(completed, total, entry.Name);
            }
        }
        progress.Report(total, total, "", force: true);
    }
}
