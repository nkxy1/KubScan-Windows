using System;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;

namespace KubScan;

// The shell owns the dialog's UI thread, so extraction can stay synchronous.
// No WinUI or additional native libraries need to be unpacked to show it.
internal sealed class ExtractionProgress : IDisposable
{
    private readonly IProgressDialog dialog;
    private readonly Stopwatch updates = Stopwatch.StartNew();

    internal ExtractionProgress()
    {
        dialog = (IProgressDialog)Activator.CreateInstance(Type.GetTypeFromCLSID(
            new Guid("F8383852-FCD3-11D1-A6B9-006097DF5BD4"), throwOnError: true));
        try
        {
            bool german = CultureInfo.CurrentUICulture.TwoLetterISOLanguageName == "de";
            dialog.SetTitle("KubScan");
            dialog.SetLine(1, german ? "KubScan wird für den ersten Start entpackt …"
                : "Unpacking KubScan for its first launch …", false, IntPtr.Zero);
            dialog.SetCancelMsg(german ? "Entpacken wird abgebrochen …"
                : "Canceling extraction …", IntPtr.Zero);
            // PROGDLG_NOTIME | PROGDLG_NOMINIMIZE; cancellation remains available.
            dialog.StartProgressDialog(IntPtr.Zero, IntPtr.Zero, 0x04 | 0x08, IntPtr.Zero);
            dialog.SetProgress64(0, 1);
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    internal void Report(long completed, long total, string file, bool force = false)
    {
        if (!force && updates.ElapsedMilliseconds < 100) return;
        if (dialog.HasUserCancelled()) throw new OperationCanceledException();
        int percent = total == 0 ? 100 : (int)(100m * completed / total);
        dialog.SetProgress64((ulong)completed, (ulong)Math.Max(total, 1));
        dialog.SetLine(2, $"{percent} %   {file}", false, IntPtr.Zero);
        updates.Restart();
    }

    public void Dispose()
    {
        try { dialog.StopProgressDialog(); }
        finally { Marshal.FinalReleaseComObject(dialog); }
    }

    // Keep native vtable order, including the unused 32-bit progress method.
    [ComImport, Guid("EBBC7C04-315E-11D2-B62F-006097DF5BD4"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IProgressDialog
    {
        void StartProgressDialog(IntPtr parent, IntPtr enableModeless, uint flags, IntPtr reserved);
        void StopProgressDialog();
        void SetTitle([MarshalAs(UnmanagedType.LPWStr)] string title);
        void SetAnimation(IntPtr instance, uint resource);
        [PreserveSig]
        [return: MarshalAs(UnmanagedType.Bool)]
        bool HasUserCancelled();
        void SetProgress(uint completed, uint total);
        void SetProgress64(ulong completed, ulong total);
        void SetLine(uint line, [MarshalAs(UnmanagedType.LPWStr)] string text,
            [MarshalAs(UnmanagedType.Bool)] bool compactPath, IntPtr reserved);
        void SetCancelMsg([MarshalAs(UnmanagedType.LPWStr)] string message, IntPtr reserved);
    }
}
