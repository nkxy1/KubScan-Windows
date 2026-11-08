using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;

namespace KubScan;

// Native UI is available before the bundled WinUI libraries are extracted.
// Report pumps messages on the extraction thread; closing cancels extraction.
internal sealed class ExtractionProgress : IDisposable
{
    private readonly Stopwatch updates = Stopwatch.StartNew();
    private readonly WindowProc procedure;
    private readonly string className = "KubScan.Preparation." + Guid.NewGuid().ToString("N");
    private readonly IntPtr instance = GetModuleHandle(null);
    private readonly bool german = CultureInfo.CurrentUICulture.TwoLetterISOLanguageName == "de";
    private IntPtr window, headingFont, detailFont, icon;
    private double scale;
    private int percent;
    private bool canceled, disposed;

    internal ExtractionProgress()
    {
        procedure = HandleMessage;
        try
        {
            scale = GetDpiForSystem() / 96.0;
            headingFont = CreateFont(-Px(24), 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, "Segoe UI");
            detailFont = CreateFont(-Px(16), 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, "Segoe UI");
            icon = LoadIcon();
            var wc = new WindowClass {
                size = (uint)Marshal.SizeOf<WindowClass>(), procedure = procedure,
                instance = instance, className = className,
                cursor = LoadCursor(IntPtr.Zero, new IntPtr(32512)), icon = icon, smallIcon = icon
            };
            if (RegisterClassEx(ref wc) == 0) throw new Win32Exception();
            const uint style = 0x00C80000; // Caption, system menu, no resizing/minimize/maximize.
            var bounds = new Rect { right = Px(538), bottom = Px(162) };
            AdjustWindowRectExForDpi(ref bounds, style, false, 0, (uint)Math.Round(scale * 96));
            int width = bounds.right - bounds.left, height = bounds.bottom - bounds.top;
            SystemParametersInfo(0x0030, 0, out Rect work, 0);
            window = CreateWindowEx(0, className, "KubScan", style,
                work.left + (work.right - work.left - width) / 2,
                work.top + (work.bottom - work.top - height) / 2,
                width, height, IntPtr.Zero, IntPtr.Zero, instance, IntPtr.Zero);
            if (window == IntPtr.Zero) throw new Win32Exception();
            int dark = 1, background = 0x202020, foreground = 0xFFFFFF;
            DwmSetWindowAttribute(window, 20, ref dark, sizeof(int));
            DwmSetWindowAttribute(window, 35, ref background, sizeof(int));
            DwmSetWindowAttribute(window, 36, ref foreground, sizeof(int));
            ShowWindow(window, 5);
            UpdateWindow(window);
        }
        catch { Dispose(); throw; }
    }

    internal void Report(long completed, long total, string file, bool force = false)
    {
        if (!force && updates.ElapsedMilliseconds < 100) return;
        while (PeekMessage(out var message, window, 0, 0, 1)) {
            TranslateMessage(ref message);
            DispatchMessage(ref message);
        }
        if (canceled) throw new OperationCanceledException();
        percent = total == 0 ? 100 : (int)Math.Clamp(100m * completed / total, 0, 100);
        InvalidateRect(window, IntPtr.Zero, false);
        UpdateWindow(window);
        updates.Restart();
    }

    private IntPtr HandleMessage(IntPtr hwnd, uint message, IntPtr wParam, IntPtr lParam)
    {
        if (message == 0x0010) { canceled = true; return IntPtr.Zero; }
        if (message == 0x0014) return new IntPtr(1);
        if (message == 0x000F) {
            var dc = BeginPaint(hwnd, out var paint);
            try {
                GetClientRect(hwnd, out var area);
                Fill(dc, area, 0x202020);
                SetBkMode(dc, 1);
                DrawLabel(dc, german ? "KubScan wird vorbereitet" : "Preparing KubScan",
                    headingFont, 0xFFFFFF, 25, 56);
                DrawLabel(dc, (german ? "Programmdateien entpacken" : "Extracting program files") + $" · {percent}%",
                    detailFont, 0xC0C0C0, 69, 96);
                var track = new Rect { left = Px(30), top = Px(117), right = area.right - Px(33), bottom = Px(127) };
                Fill(dc, track, 0x3B3B3B);
                track.right = track.left + (track.right - track.left) * percent / 100;
                Fill(dc, track, 0xD6B532); // COLORREF for #32B5D6.
            }
            finally { EndPaint(hwnd, ref paint); }
            return IntPtr.Zero;
        }
        return DefWindowProc(hwnd, message, wParam, lParam);
    }

    private void DrawLabel(IntPtr dc, string text, IntPtr font, uint color, int y, int bottom)
    {
        var previous = SelectObject(dc, font);
        SetTextColor(dc, color);
        var rect = new Rect { left = Px(30), top = Px(y), right = Px(520), bottom = Px(bottom) };
        DrawText(dc, text, -1, ref rect, 0x20 | 0x800);
        SelectObject(dc, previous);
    }

    private static void Fill(IntPtr dc, Rect rect, uint color)
    {
        var brush = CreateSolidBrush(color);
        try { FillRect(dc, ref rect, brush); }
        finally { DeleteObject(brush); }
    }

    private IntPtr LoadIcon()
    {
        using var stream = typeof(ExtractionProgress).Assembly.GetManifestResourceStream("KubScan.ico")
            ?? throw new InvalidDataException("Missing KubScan icon.");
        using var reader = new BinaryReader(stream);
        reader.ReadUInt16(); reader.ReadUInt16();
        int count = reader.ReadUInt16(), best = int.MaxValue;
        uint length = 0, offset = 0;
        for (int i = 0; i < count; i++) {
            int width = reader.ReadByte();
            reader.ReadByte(); reader.ReadUInt16(); reader.ReadUInt16(); reader.ReadUInt16();
            uint size = reader.ReadUInt32(), position = reader.ReadUInt32();
            int distance = Math.Abs((width == 0 ? 256 : width) - Px(32));
            if (distance < best) { best = distance; length = size; offset = position; }
        }
        stream.Position = offset;
        var bytes = reader.ReadBytes(checked((int)length));
        var result = CreateIconFromResourceEx(bytes, (uint)bytes.Length, true, 0x00030000, Px(32), Px(32), 0);
        if (result == IntPtr.Zero) throw new Win32Exception();
        return result;
    }

    private int Px(int value) => (int)Math.Round(value * scale);

    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        if (window != IntPtr.Zero) DestroyWindow(window);
        UnregisterClass(className, instance);
        if (headingFont != IntPtr.Zero) DeleteObject(headingFont);
        if (detailFont != IntPtr.Zero) DeleteObject(detailFont);
        if (icon != IntPtr.Zero) DestroyIcon(icon);
        GC.KeepAlive(procedure);
    }

    private delegate IntPtr WindowProc(IntPtr hwnd, uint message, IntPtr wParam, IntPtr lParam);
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WindowClass {
        public uint size, style;
        public WindowProc procedure;
        public int classExtra, windowExtra;
        public IntPtr instance, icon, cursor, background;
        public string menuName, className;
        public IntPtr smallIcon;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct Rect { public int left, top, right, bottom; }
    [StructLayout(LayoutKind.Sequential)]
    private struct Message {
        public IntPtr hwnd;
        public uint message;
        public UIntPtr wParam;
        public IntPtr lParam;
        public uint time;
        public int x, y;
        public uint reserved;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct Paint {
        public IntPtr dc;
        public int erase;
        public Rect rect;
        public int restore, update;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)] public byte[] reserved;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr GetModuleHandle(string name);
    [DllImport("user32.dll")] private static extern uint GetDpiForSystem();
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern ushort RegisterClassEx(ref WindowClass value);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern bool UnregisterClass(string name, IntPtr instance);
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr CreateWindowEx(uint extended, string className, string title, uint style, int x, int y, int width, int height, IntPtr parent, IntPtr menu, IntPtr instance, IntPtr parameter);
    [DllImport("user32.dll")] private static extern bool AdjustWindowRectExForDpi(ref Rect rect, uint style, bool menu, uint extended, uint dpi);
    [DllImport("user32.dll")] private static extern bool SystemParametersInfo(uint action, uint parameter, out Rect value, uint flags);
    [DllImport("user32.dll")] private static extern bool ShowWindow(IntPtr hwnd, int command);
    [DllImport("user32.dll")] private static extern bool UpdateWindow(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern bool DestroyWindow(IntPtr hwnd);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr DefWindowProc(IntPtr hwnd, uint message, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll")] private static extern bool PeekMessage(out Message message, IntPtr hwnd, uint min, uint max, uint flags);
    [DllImport("user32.dll")] private static extern bool TranslateMessage(ref Message message);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr DispatchMessage(ref Message message);
    [DllImport("user32.dll")] private static extern bool InvalidateRect(IntPtr hwnd, IntPtr rect, bool erase);
    [DllImport("user32.dll")] private static extern bool GetClientRect(IntPtr hwnd, out Rect rect);
    [DllImport("user32.dll")] private static extern IntPtr BeginPaint(IntPtr hwnd, out Paint paint);
    [DllImport("user32.dll")] private static extern bool EndPaint(IntPtr hwnd, ref Paint paint);
    [DllImport("user32.dll")] private static extern int FillRect(IntPtr dc, ref Rect rect, IntPtr brush);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int DrawText(IntPtr dc, string text, int count, ref Rect rect, uint flags);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr LoadCursor(IntPtr instance, IntPtr name);
    [DllImport("user32.dll", SetLastError = true)] private static extern IntPtr CreateIconFromResourceEx(byte[] bytes, uint size, bool icon, uint version, int width, int height, uint flags);
    [DllImport("user32.dll")] private static extern bool DestroyIcon(IntPtr icon);
    [DllImport("gdi32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr CreateFont(int height, int width, int escapement, int orientation, int weight, uint italic, uint underline, uint strikeout, uint charset, uint precision, uint clip, uint quality, uint pitch, string face);
    [DllImport("gdi32.dll")] private static extern IntPtr SelectObject(IntPtr dc, IntPtr value);
    [DllImport("gdi32.dll")] private static extern bool DeleteObject(IntPtr value);
    [DllImport("gdi32.dll")] private static extern IntPtr CreateSolidBrush(uint color);
    [DllImport("gdi32.dll")] private static extern int SetBkMode(IntPtr dc, int mode);
    [DllImport("gdi32.dll")] private static extern uint SetTextColor(IntPtr dc, uint color);
    [DllImport("dwmapi.dll")] private static extern int DwmSetWindowAttribute(IntPtr hwnd, uint attribute, ref int value, int size);
}
