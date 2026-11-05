namespace KubScan.WinUI;

internal static partial class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length == 0)
        {
            StartGui();
            return 0;
        }

        if (args[0] == "--tui")
        {
            if (Console.IsInputRedirected || Console.IsOutputRedirected)
            {
                Console.Error.WriteLine("KubScan --tui requires an interactive terminal.");
                return 1;
            }
            return global::KubScan.Launcher.Main(args[1..]);
        }

        return global::KubScan.Launcher.Main(args);
    }

    static partial void InitializeGuiRuntime();

    // Do not let JIT compilation of the CLI entry point pull in XAML types.
    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    private static void StartGui()
    {
        InitializeGuiRuntime();
        XamlGeneratedProgram.XamlGeneratedMain();
    }
}
