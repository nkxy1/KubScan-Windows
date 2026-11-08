using System.IO.Compression;
using System.Reflection;
using KubScan;

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        using var progress = new ExtractionProgress();
        if (args.Contains("--preview"))
        {
            try
            {
                for (int i = 0; i < 600; i++)
                {
                    progress.Report(i % 100, 100, "KubScan.WinUI.dll", force: true);
                    Thread.Sleep(100);
                }
                throw new Exception("Preview was not canceled within 60 seconds.");
            }
            catch (OperationCanceledException)
            {
                Console.WriteLine("OK: Progress dialog cancellation detected.");
                return;
            }
        }

        var staging = Path.Combine(Path.GetTempPath(), "KubScan-extraction-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(staging);
        try
        {
            var bytes = new byte[350_000];
            new Random(42).NextBytes(bytes);
            using var zip = new MemoryStream();
            using (var writer = new ZipArchive(zip, ZipArchiveMode.Create, leaveOpen: true))
            {
                writer.CreateEntry("empty/");
                writer.CreateEntry("empty/zero.txt");
                using var file = writer.CreateEntry("nested/Grüße.bin").Open();
                file.Write(bytes);
            }
            zip.Position = 0;
            using (var archive = new ZipArchive(zip, ZipArchiveMode.Read)) Extract(archive, staging, progress);
            if (!File.ReadAllBytes(Path.Combine(staging, "nested/Grüße.bin")).SequenceEqual(bytes)
                || new FileInfo(Path.Combine(staging, "empty/zero.txt")).Length != 0)
                throw new Exception("Extraction changed file contents or missed empty files.");

            using var malicious = new MemoryStream();
            using (var writer = new ZipArchive(malicious, ZipArchiveMode.Create, leaveOpen: true))
                writer.CreateEntry("../escape.txt");
            malicious.Position = 0;
            using var badArchive = new ZipArchive(malicious, ZipArchiveMode.Read);
            try
            {
                Extract(badArchive, staging, progress);
                throw new Exception("ZIP path traversal was accepted.");
            }
            catch (InvalidDataException) { }
            Console.WriteLine("OK: Multi-buffer extraction, nested and Unicode paths, empty files, ZIP traversal protection.");
        }
        finally { Directory.Delete(staging, recursive: true); }
    }

    private static void Extract(ZipArchive archive, string staging, ExtractionProgress progress)
    {
        var extract = typeof(PortableGui).GetMethod("ExtractArchive", BindingFlags.NonPublic | BindingFlags.Static);
        try { extract.Invoke(null, [archive, staging, progress]); }
        catch (TargetInvocationException error) when (error.InnerException != null)
        {
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(error.InnerException).Throw();
        }
    }
}
