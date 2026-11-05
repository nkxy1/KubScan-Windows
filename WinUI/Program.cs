namespace KubScan.WinUI;

internal static class Program
{
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
            if (Console.IsInputRedirected || Console.IsOutputRedirected)
            {
                Console.Error.WriteLine("KubScan --tui requires an interactive terminal.");
                return 1;
            }
            return global::KubScan.Launcher.Main(args[1..]);
        }

        return global::KubScan.Launcher.Main(args);
    }
}
