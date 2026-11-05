using System.Runtime.InteropServices;

namespace KubScan.WinUI;

internal static class Program
{
    private const uint AttachParentProcess = uint.MaxValue;
    private const int StandardInput = -10;
    private const int StandardOutput = -11;
    private const int StandardError = -12;

    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length == 0)
        {
            XamlGeneratedProgram.XamlGeneratedMain();
            return 0;
        }

        if (args[0] == "--tui")
        {
            if (!HasInteractiveConsole()) AttachConsole(AttachParentProcess);
            if (!HasInteractiveConsole())
            {
                Console.Error.WriteLine("KubScan --tui requires an interactive terminal.");
                return 1;
            }
            return global::KubScan.Launcher.Main(args[1..]);
        }

        ConnectCommandLineOutput();
        return global::KubScan.Launcher.Main(args);
    }

    private static bool HasInteractiveConsole() =>
        GetConsoleMode(GetStdHandle(StandardInput), out _) &&
        GetConsoleMode(GetStdHandle(StandardOutput), out _);

    private static void ConnectCommandLineOutput()
    {
        IntPtr output = GetStdHandle(StandardOutput);
        IntPtr error = GetStdHandle(StandardError);
        bool hasOutput = IsValid(output);
        bool hasError = IsValid(error);

        if (hasOutput && hasError) return;
        if (!AttachConsole(AttachParentProcess)) return;

        // AttachConsole can replace inherited handles. Keep any file or pipe
        // already supplied by the caller.
        if (hasOutput) SetStdHandle(StandardOutput, output);
        if (hasError) SetStdHandle(StandardError, error);
    }

    private static bool IsValid(IntPtr handle) => handle != IntPtr.Zero && handle != new IntPtr(-1);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetConsoleMode(IntPtr handle, out uint mode);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AttachConsole(uint processId);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern IntPtr GetStdHandle(int handle);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetStdHandle(int handle, IntPtr value);
}
