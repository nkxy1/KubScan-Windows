using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Windows.ApplicationModel.DataTransfer;
using Windows.System;
using Backend = KubScan.App.Desktop;

namespace KubScan.WinUI;

public sealed partial class MainWindow : Window
{
    private readonly TableColumnWidths[] tableColumns = [new(4), new(5), new(5)];
    private readonly string[] filters = ["", "", ""];
    private readonly int[] sort = new int[3];
    private readonly bool[] descending = new bool[3];
    private readonly object[] selections = new object[3];
    private readonly ResultCollection rows = new();
    private Backend.Row[] renderedSnapshot;
    private List<TargetHistoryEntry> targetHistory = [];
    private readonly DispatcherTimer timer = new() { Interval = TimeSpan.FromMilliseconds(350) };
    private Backend.Mode mode;
    private Backend.HostTool activeTool;
    private bool ready, busy, updating, closing, allowClose;
    private string notice = "";
    private string adapterLabel;
    private bool narrowToolbar, compactToolbar;
    private bool detailOnRight;
    private double detailWidth = 300, detailHeight = 152;
    private object displayedDetailKey;
    private Backend.DetailField[] renderedFields = [];
    private int renderedDetailColumns;
    private Backend.Mode displayedDetailMode;
    private static readonly string LayoutPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "KubScan", "winui-layout.txt");
    private static readonly string HistoryPath = Path.Combine(Path.GetDirectoryName(LayoutPath), "winui-target-history.json");
    private sealed record TargetHistoryEntry(string Address, long Uses);
    private ContentDialog openDialog;
    private static readonly string ThemePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "KubScan", "winui-theme.txt");

    public MainWindow()
    {
        global::KubScan.App.English = System.Globalization.CultureInfo.CurrentUICulture.TwoLetterISOLanguageName != "de";
        InitializeComponent();
        Title = "KubScan " + global::KubScan.App.Version;
        AppVersion.Text = global::KubScan.App.Version;
        AppWindow.SetIcon(Path.Combine(AppContext.BaseDirectory, "Kubscan.ico"));
        SystemBackdrop = new MicaBackdrop();
        if (AppWindowTitleBar.IsCustomizationSupported())
        {
            ExtendsContentIntoTitleBar = true;
            SetTitleBar(AppTitleBar);
            AppWindow.TitleBar.PreferredHeightOption = TitleBarHeightOption.Tall;
        }
        else TitleBarFrame.Visibility = Visibility.Collapsed;
        RestoreTheme();
        AppWindow.Resize(new Windows.Graphics.SizeInt32(1500, 1380));
        PreferRoundedCorners();
        AppWindow.Closing += Closing;
        Results.ItemsSource = rows;
        timer.Tick += (_, _) => Refresh();
        UpdateModeButtons();
        Root.Loaded += Initialize;
        Root.SizeChanged += (_, _) => ArrangeToolbar();
        ContentArea.SizeChanged += (_, _) => ArrangeDetails();
        TableCard.SizeChanged += (_, _) => ResizeTable();
        DetailScroll.SizeChanged += (_, _) => { if (ready) RefreshDetails(); };
        AddShortcut(VirtualKey.F2, () => StartOrStop(false));
        AddShortcut(VirtualKey.F3, ToggleContinuousOption);
        AddShortcut(VirtualKey.F7, () => { OpenSearch(); return Task.CompletedTask; });
        AddShortcut(VirtualKey.F9, async () => { await Backend.StopAsync(mode); Refresh(); });
        AddShortcut(VirtualKey.F1, ShowHelp);
        AddShortcut(VirtualKey.C, CopySelectedColumn, VirtualKeyModifiers.Control);
    }

    private void PreferRoundedCorners()
    {
        if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22000)) return;

        const int DWMWA_WINDOW_CORNER_PREFERENCE = 33;
        const int DWMWCP_ROUND = 2;
        int preference = DWMWCP_ROUND;
        var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(this);
        // DWM decides when rounding is appropriate, including after snap or maximize.
        _ = DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, in preference, sizeof(int));
    }

    [DllImport("dwmapi.dll", ExactSpelling = true)]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, in int value, int size);

    private static string L(string de, string en) => Backend.Text(de, en);

    private async void Initialize(object sender, RoutedEventArgs args)
    {
        Root.Loaded -= Initialize;
        SetControlsEnabled(false);
        Status.Text = L("KubScan wird geladen …", "Loading KubScan …");
        try
        {
            var defaultTarget = Task.Run(Backend.DefaultTarget);
            await Task.WhenAll(Backend.InitializeAsync(), defaultTarget);
            Target.Text = defaultTarget.Result;
        }
        catch (Exception error) { notice = error.Message; }
        if (closing) return;
        ready = true;
        SetControlsEnabled(true);
        RestoreLayout();
        RestoreTargetHistory();
        ArrangeDetails();
        UpdateLabels();
        Refresh();
        timer.Start();
    }

    private void SetControlsEnabled(bool enabled)
    {
        foreach (var control in new Control[] { Target, TargetHistoryButton, AdapterButton, StartButton, ContinuousSwitch, SearchToggle, Search, ExportButton, MoreButton, IpTab, MdnsTab, ArpTab })
            control.IsEnabled = enabled;
    }

    private void ArrangeToolbar()
    {
        bool narrow = Root.ActualWidth < 900;
        bool compact = Root.ActualWidth < 660;
        if (narrowToolbar == narrow && compactToolbar == compact) return;
        narrowToolbar = narrow;
        compactToolbar = compact;

        Grid.SetColumn(ModeSelector, narrow ? 0 : 1);
        Grid.SetColumnSpan(ModeSelector, narrow ? 3 : 1);
        Grid.SetRow(ScanControls, narrow ? 1 : 0);
        Grid.SetColumnSpan(ScanControls, narrow ? 3 : 1);
        Grid.SetRow(ToolbarActions, compact ? 2 : narrow ? 1 : 0);
        Grid.SetColumn(ToolbarActions, narrow ? 0 : 2);
        Grid.SetColumnSpan(ToolbarActions, narrow ? 3 : 1);
        ScanControls.Margin = new Thickness(0, narrow ? 8 : 0, 0, 0);
        ToolbarActions.Margin = new Thickness(0, narrow ? 8 : 0, 0, 0);
    }

    private void AddShortcut(VirtualKey key, Func<Task> action, VirtualKeyModifiers modifiers = 0)
    {
        var accelerator = new KeyboardAccelerator { Key = key, Modifiers = modifiers };
        accelerator.Invoked += async (_, args) =>
        {
            if (!ready || busy || closing) return;
            if (key == VirtualKey.C && FocusManager.GetFocusedElement(Root.XamlRoot) is TextBox) return;
            args.Handled = true;
            await Perform(action);
        };
        Root.KeyboardAccelerators.Add(accelerator);
    }

    private async Task Perform(Func<Task> action)
    {
        if (busy || closing || !ready) return;
        busy = true;
        try { await action(); }
        catch (Exception error) { notice = error.Message; }
        finally { busy = false; if (!closing) Refresh(); }
    }

    private void UpdateLabels()
    {
        AppTitleBarSubtitle.Text = L("Netzwerkscanner", "Network Scanner");
        Target.PlaceholderText = L("Subnetz / IP-Bereich", "Subnet / IP range");
        AutomationProperties.SetName(Target, Target.PlaceholderText);
        Search.PlaceholderText = L("Suchen …", "Search …");
        AutomationProperties.SetName(Search, Search.PlaceholderText);
        var searchAction = L("Suche anzeigen oder ausblenden", "Show or hide search");
        AutomationProperties.SetName(SearchToggle, searchAction);
        ToolTipService.SetToolTip(SearchToggle, searchAction);
        AutomationProperties.SetName(MoreButton, L("Weitere Aktionen", "More actions"));
        LocalNetwork.Text = L("Lokales Netzwerk", "Local network");
        var export = L("Exportieren", "Export");
        AutomationProperties.SetName(ExportButton, export);
        ToolTipService.SetToolTip(ExportButton, export);
        AdapterLabel.Text = adapterLabel ?? L("Alle Adapter", "All adapters");
        AutomationProperties.SetName(AdapterButton, AdapterLabel.Text);
        TargetInput.Visibility = Show(mode == Backend.Mode.Ip);
        var historyLabel = L("Verlauf der Scanbereiche", "Scan range history");
        AutomationProperties.SetName(TargetHistoryButton, historyLabel);
        ToolTipService.SetToolTip(TargetHistoryButton, historyLabel);
        AdapterButton.Visibility = Show(mode == Backend.Mode.Arp);
        LocalNetwork.Visibility = Show(mode == Backend.Mode.Mdns);
        ExportButton.Visibility = Show(mode != Backend.Mode.Arp);
        ContinuousSwitch.Visibility = Show(mode == Backend.Mode.Ip);
        var continuousLabel = L("Dauerscan", "Continuous scan");


        AutomationProperties.SetName(ContinuousSwitch, continuousLabel);
        ToolTipService.SetToolTip(ContinuousSwitch, continuousLabel);
        UpdatePlacementLabel();
        var resize = L("Detailbereich vergrößern oder verkleinern", "Resize detail pane");
        foreach (var grip in new[] { BelowGrip, RightGrip })
        {
            AutomationProperties.SetName(grip, resize);
            ToolTipService.SetToolTip(grip, resize);
        }
        RebuildHeaders();
        ResizeTable();
        RebuildMenu();
    }

    private static Visibility Show(bool visible) => visible ? Visibility.Visible : Visibility.Collapsed;

    private void ResizeTable()
    {
        // One surface keeps the header and rows aligned when the table scrolls sideways.
        double minimum = mode == Backend.Mode.Ip ? 550 : 660;
        double width = Math.Max(Math.Max(minimum, tableColumns[(int)mode].MinimumTableWidth), Math.Floor(TableCard.ActualWidth) - 2);
        if (TableSurface.Width != width) TableSurface.Width = width;
    }

    private void RebuildHeaders()
    {
        Headers.Children.Clear();
        Headers.ColumnDefinitions.Clear();
        var headings = Backend.Headers(mode);
        var widths = tableColumns[(int)mode];
        Headers.ColumnDefinitions.Add(new ColumnDefinition { Width = widths.StatusWidth });
        if (widths.ShowStatus)
        {
            Headers.Children.Add(new TextBlock
            {
                Text = "Status",
                FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            });
        }
        if (mode == Backend.Mode.Arp) HeaderBand.Background = new SolidColorBrush(Microsoft.UI.Colors.Transparent);
        else HeaderBand.ClearValue(Border.BackgroundProperty);
        for (int i = 0; i < headings.Length; i++)
        {
            int column = i;
            Headers.ColumnDefinitions.Add(new ColumnDefinition { Width = widths[i] });
            var heading = new Button
            {
                Tag = headings[i], HorizontalAlignment = HorizontalAlignment.Stretch,
                HorizontalContentAlignment = HorizontalAlignment.Left, Padding = new Thickness(8, 0, 12, 0),
                BorderThickness = new Thickness(0), CornerRadius = new CornerRadius(0),
                Background = new SolidColorBrush(Microsoft.UI.Colors.Transparent), MinHeight = 32
            };
            heading.Click += (_, _) =>
            {
                int view = (int)mode;
                descending[view] = sort[view] == column && !descending[view];
                sort[view] = column;
                UpdateSortHeaders();
                Refresh();
            };
            var fit = new DoubleTappedEventHandler((_, args) =>
            {
                FitColumn(column, headings[column]);
                args.Handled = true;
            });
            heading.AddHandler(UIElement.DoubleTappedEvent, fit, true);
            Grid.SetColumn(heading, i + 1);
            Headers.Children.Add(heading);

            var grip = new Thumb
            {
                Style = (Style)Root.Resources["ColumnGripStyle"],
                HorizontalAlignment = HorizontalAlignment.Right,
                VerticalAlignment = VerticalAlignment.Stretch,
                IsTabStop = true,
                Width = 12
            };
            var resize = L("Spaltenbreite ändern: ", "Resize column: ") + headings[i];
            AutomationProperties.SetName(grip, resize);
            ToolTipService.SetToolTip(grip, resize);
            grip.DragDelta += (_, args) => ResizeColumn(column, args.HorizontalChange);
            grip.AddHandler(UIElement.DoubleTappedEvent, fit, true);
            grip.KeyDown += (_, args) =>
            {
                if (args.Key is not (VirtualKey.Left or VirtualKey.Right)) return;
                ResizeColumn(column, args.Key == VirtualKey.Right ? 12 : -12);
                args.Handled = true;
            };
            Grid.SetColumn(grip, i + 1);
            Headers.Children.Add(grip);
        }
        UpdateSortHeaders();
    }

    private void ResizeColumn(int column, double change)
    {
        var definition = Headers.ColumnDefinitions[column + 1];
        var widths = tableColumns[(int)mode];
        widths.Resize(column, (definition.Width.IsAbsolute ? definition.Width.Value : definition.ActualWidth) + change);
        definition.Width = widths[column];
        ResizeTable();
    }

    private void FitColumn(int column, string heading)
    {
        var measure = new TextBlock
        {
            FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
            Text = heading + "  ↑"
        };
        var available = new Windows.Foundation.Size(double.PositiveInfinity, double.PositiveInfinity);
        measure.Measure(available);
        double width = measure.DesiredSize.Width;
        measure.FontWeight = Microsoft.UI.Text.FontWeights.Normal;
        foreach (var item in rows)
        {
            measure.Text = column == 0 ? item.First : item.Row.Cells[column];
            measure.Measure(available);
            width = Math.Max(width, measure.DesiredSize.Width);
        }
        var definition = Headers.ColumnDefinitions[column + 1];
        ResizeColumn(column, Math.Ceiling(width) + 24 -
            (definition.Width.IsAbsolute ? definition.Width.Value : definition.ActualWidth));
    }

    private void UpdateSortHeaders()
    {
        foreach (var header in Headers.Children.OfType<Button>())
        {
            bool active = Grid.GetColumn(header) == sort[(int)mode] + 1;
            string heading = (string)header.Tag;
            bool reverse = descending[(int)mode];
            string direction = reverse ? L("absteigend", "descending") : L("aufsteigend", "ascending");
            AutomationProperties.SetName(header, active ? heading + ", " + direction : L("Sortieren nach ", "Sort by ") + heading);
            header.Content = new TextBlock
            {
                Text = heading + (active ? (reverse ? "  ↓" : "  ↑") : ""),
                TextTrimming = TextTrimming.CharacterEllipsis,
                FontWeight = Microsoft.UI.Text.FontWeights.SemiBold
            };
        }
    }

    private void RestoreLayout()
    {
        try { detailOnRight = File.Exists(LayoutPath) && File.ReadAllText(LayoutPath).Trim() == "right"; }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        UpdateDetailPlacement();
    }

    private void UpdateDetailPlacement()
    {
        UpdatePlacementLabel();
        BelowGrip.Visibility = Show(!detailOnRight);
        RightGrip.Visibility = Show(detailOnRight);
        Grid.SetRow(DetailCard, detailOnRight ? 0 : 2);
        Grid.SetColumn(DetailCard, detailOnRight ? 2 : 0);
        Grid.SetRow(DetailTitle, detailOnRight ? 1 : 0);
        Grid.SetColumnSpan(DetailTitle, detailOnRight ? 2 : 1);
        ArrangeDetails();
    }

    private void UpdatePlacementLabel()
    {
        var label = detailOnRight ? L("Nach unten", "Move below") : L("Nach rechts", "Move right");
        DetailPlacementIcon.Glyph = detailOnRight ? "\uE74B" : "\uE72A";
        AutomationProperties.SetName(DetailPlacement, label);
        ToolTipService.SetToolTip(DetailPlacement, label);
    }

    private async void DetailPlacementClicked(object sender, RoutedEventArgs args)
    {
        detailOnRight = !detailOnRight;
        UpdateDetailPlacement();
        try
        {
            string position = detailOnRight ? "right" : "below";
            await Task.Run(() => SavePreference(LayoutPath, position));
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            notice = error.Message;
            Refresh();
        }
    }

    private void ArrangeDetails()
    {
        GripRow.Height = new GridLength(detailOnRight ? 0 : 10);
        GripColumn.Width = new GridLength(detailOnRight ? 10 : 0);
        DetailRow.Height = new GridLength(detailOnRight ? 0 : PaneSize(detailHeight, ContentArea.ActualHeight, 92, 100));
        DetailColumn.Width = new GridLength(detailOnRight ? PaneSize(detailWidth, ContentArea.ActualWidth, 216, 240) : 0);
    }

    private static double PaneSize(double requested, double available, double minimum, double listMinimum)
    {
        if (available <= 0) return requested;
        double maximum = Math.Max(0, Math.Max(available * 0.45, available - listMinimum - 10));
        return Math.Clamp(requested, Math.Min(minimum, maximum), maximum);
    }

    private void ResizeDetails(double change)
    {
        if (detailOnRight) detailWidth = PaneSize(DetailColumn.ActualWidth + change, ContentArea.ActualWidth, 216, 240);
        else detailHeight = PaneSize(DetailRow.ActualHeight + change, ContentArea.ActualHeight, 92, 100);
        ArrangeDetails();
    }

    private void DetailDragDelta(object sender, DragDeltaEventArgs args) =>
        ResizeDetails(detailOnRight ? -args.HorizontalChange : -args.VerticalChange);

    private void DetailGripKeyDown(object sender, KeyRoutedEventArgs args)
    {
        double change = (detailOnRight, args.Key) switch
        {
            (true, VirtualKey.Left) or (false, VirtualKey.Up) => 16,
            (true, VirtualKey.Right) or (false, VirtualKey.Down) => -16,
            _ => 0
        };
        if (change == 0) return;
        args.Handled = true;
        ResizeDetails(change);
    }

    private void RebuildMenu()
    {
        var menu = new MenuFlyout { Placement = FlyoutPlacementMode.BottomEdgeAlignedRight };
        void Add(string caption, Func<Task> action)
        {
            var item = new MenuFlyoutItem { Text = caption };
            item.Click += async (_, _) => await Perform(action);
            menu.Items.Add(item);
        }
        if (mode == Backend.Mode.Ip)
        {
            Add(L("OUI-Datenbank aktualisieren", "Update OUI database"), OuiUpdate);
        }
        if (mode == Backend.Mode.Arp)
            Add(L("Mitschnitt zurücksetzen", "Reset capture"), () => StartOrStop(true));
        menu.Items.Add(new MenuFlyoutSeparator());
        Add(L("Sprache: Deutsch / Englisch", "Language: German / English"), () =>
        {
            global::KubScan.App.English = !global::KubScan.App.English;
            notice = "";
            UpdateLabels();
            return Task.CompletedTask;
        });
        var themes = new MenuFlyoutSubItem { Text = L("Design", "Theme") };
        foreach (var (theme, caption) in new[]
        {
            (ElementTheme.Light, L("Hell (Standard)", "Light (default)")),
            (ElementTheme.Dark, L("Dunkel", "Dark"))
        })
        {
            var item = new MenuFlyoutItem { Text = caption };
            item.Click += async (_, _) => await Perform(async () =>
            {
                ApplyTheme(theme);
                await Task.Run(() => SavePreference(ThemePath, theme.ToString()));
            });
            themes.Items.Add(item);
        }
        menu.Items.Add(themes);
        Add(L("Hilfe", "Help"), ShowHelp);
        MoreButton.Flyout = menu;
    }

    private async void ModeChanged(object sender, RoutedEventArgs args)
    {
        var next = ReferenceEquals(sender, IpTab) ? Backend.Mode.Ip : ReferenceEquals(sender, MdnsTab) ? Backend.Mode.Mdns : Backend.Mode.Arp;
        UpdateModeButtons();
        if (!ready || updating || closing || busy || mode == next) return;
        await Perform(async () =>
        {
            if (mode == Backend.Mode.Arp) await Backend.StopAsync(mode);
            selections[(int)mode] = (Results.SelectedItem as ResultItem)?.Row.Key;
            mode = next;
            UpdateModeButtons();
            notice = "";
            updating = true;
            rows.Clear();
            Search.Text = filters[(int)mode];
            if (Search.Text.Length > 0) Search.Visibility = Visibility.Visible;
            updating = false;
            UpdateLabels();
            Backend.EnterMode(mode);
        });
    }

    private void UpdateModeButtons()
    {
        IpTab.IsChecked = mode == Backend.Mode.Ip;
        MdnsTab.IsChecked = mode == Backend.Mode.Mdns;
        ArpTab.IsChecked = mode == Backend.Mode.Arp;
    }

    private void TargetBeforeTextChanging(TextBox sender, TextBoxBeforeTextChangingEventArgs args) =>
        args.Cancel = args.NewText.Any(c => c is not (>= '0' and <= '9' or '.' or '/' or '-'));

    private async void TargetKeyDown(object sender, KeyRoutedEventArgs args)
    {
        if (args.Key != VirtualKey.Enter) return;
        args.Handled = true;
        await Perform(() => StartOrStop(false, true));
    }

    private async void StartClicked(object sender, RoutedEventArgs args) => await Perform(() => StartOrStop(false));

    private Task ToggleContinuousOption()
    {
        if (mode != Backend.Mode.Ip) return StartOrStop(true);
        if (ContinuousSwitch.IsEnabled) ContinuousSwitch.IsChecked = ContinuousSwitch.IsChecked != true;
        return Task.CompletedTask;
    }

    private async Task StartOrStop(bool alternate, bool fromInput = false)
    {
        notice = "";
        if (mode == Backend.Mode.Arp && alternate)
        {
            await Backend.StopAsync(mode);
            Backend.RestartArp();
        }
        else if (Backend.Progress(mode, rows.Count).Running)
        {
            if (!fromInput && (!alternate || Backend.IsContinuous)) await Backend.StopAsync(mode);
            else if (alternate) notice = L("Ein Scan läuft bereits.", "A scan is already running.");
        }
        else if (mode == Backend.Mode.Ip)
        {
            string target = Target.Text.Trim();
            if (target.Length > 0 && !target.Contains('/') && !target.Contains('-'))
            {
                var prefix = new ComboBox { ItemsSource = Backend.Prefixes(target), SelectedIndex = 8, HorizontalAlignment = HorizontalAlignment.Stretch };
                var dialog = Dialog(L("CIDR-Subnetzmaske", "CIDR subnet mask"), prefix, L("Scan starten", "Start scan"));
                if (await ShowDialog(dialog) != ContentDialogResult.Primary) return;
                target += "/" + (32 - prefix.SelectedIndex);
                Target.Text = target;
            }
            StartIp(target, ContinuousSwitch.IsChecked == true);
            await RememberTarget(Backend.LastTarget());
        }
        else Backend.EnterMode(mode);
    }

    private void StartIp(string target, bool continuous)
    {
        Backend.StartIp(target, continuous);
        if (continuous) return;
        filters[(int)mode] = "";
        Search.Text = "";
        selections[(int)mode] = null;
        Results.SelectedItem = null;
    }

    private void RestoreTargetHistory()
    {
        try
        {
            if (File.Exists(HistoryPath))
                targetHistory = JsonSerializer.Deserialize<List<TargetHistoryEntry>>(File.ReadAllText(HistoryPath)) ?? [];
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException) { }
    }

    private Task RememberTarget(string address)
    {
        int index = targetHistory.FindIndex(entry => entry.Address == address);
        long uses = index >= 0 ? targetHistory[index].Uses : 0;
        if (index >= 0) targetHistory.RemoveAt(index);
        targetHistory.Insert(0, new TargetHistoryEntry(address, uses + 1));
        string savedHistory = JsonSerializer.Serialize(targetHistory);
        return Task.Run(() => SavePreference(HistoryPath, savedHistory));
    }

    private void TargetHistoryClicked(object sender, RoutedEventArgs args)
    {
        if (!ready || busy || closing) return;
        var presenterStyle = new Style(typeof(MenuFlyoutPresenter));
        presenterStyle.Setters.Add(new Setter(FrameworkElement.WidthProperty, TargetInput.ActualWidth));
        var menu = new MenuFlyout
        {
            Placement = FlyoutPlacementMode.BottomEdgeAlignedLeft,
            MenuFlyoutPresenterStyle = presenterStyle
        };

        void AddHeading(string label) => menu.Items.Add(new MenuFlyoutItem { Text = label, IsEnabled = false });
        void AddAddress(TargetHistoryEntry entry)
        {
            var item = new MenuFlyoutItem { Text = entry.Address, FontSize = 13 };
            item.Click += (_, _) => Target.Text = entry.Address;
            menu.Items.Add(item);
        }

        var frequent = targetHistory.Where(entry => entry.Uses > 1).OrderByDescending(entry => entry.Uses).Take(3).ToArray();
        var recent = targetHistory.Except(frequent).Take(10).ToArray();
        if (frequent.Length > 0)
        {
            AddHeading(L("Häufig verwendet", "Frequently used"));
            foreach (var entry in frequent) AddAddress(entry);
        }
        if (recent.Length > 0)
        {
            if (frequent.Length > 0) menu.Items.Add(new MenuFlyoutSeparator());
            AddHeading(L("Zuletzt verwendet", "Recently used"));
            foreach (var entry in recent) AddAddress(entry);
        }
        if (menu.Items.Count == 0) AddHeading(L("Noch keine Scanbereiche", "No scan ranges yet"));
        menu.ShowAt(TargetInput);
    }

    private async void ChooseAdapter(object sender, RoutedEventArgs args) => await Perform(async () =>
    {
        var choices = await Backend.AdaptersAsync();
        var list = new ListView { ItemsSource = choices, MaxHeight = 300,
            SelectedIndex = Math.Max(0, Array.FindIndex(choices, a => a.Key == Backend.AdapterKey)) };
        var dialog = Dialog(L("ARP-Adapter", "ARP adapter"), list, L("Übernehmen", "Apply"));
        if (await ShowDialog(dialog) != ContentDialogResult.Primary || list.SelectedItem is not Backend.Adapter adapter) return;
        await Backend.SelectAdapterAsync(adapter);
        adapterLabel = adapter.Key.Length == 0 ? null : adapter.Label;
        UpdateLabels();
    });

    private void OpenSearch()
    {
        Search.Visibility = Visibility.Visible;
        Search.Focus(FocusState.Keyboard);
    }

    private void CloseSearch()
    {
        Search.Text = "";
        Search.Visibility = Visibility.Collapsed;
        SearchToggle.Focus(FocusState.Keyboard);
    }

    private void SearchToggleClicked(object sender, RoutedEventArgs args)
    {
        if (Search.Visibility == Visibility.Visible) CloseSearch();
        else OpenSearch();
    }

    private void SearchKeyDown(object sender, KeyRoutedEventArgs args)
    {
        if (args.Key != VirtualKey.Escape) return;
        args.Handled = true;
        CloseSearch();
    }

    private void SearchChanged(object sender, TextChangedEventArgs args)
    {
        if (!ready || updating) return;
        filters[(int)mode] = Search.Text;
        Refresh();
    }

    private void SelectionChanged(object sender, SelectionChangedEventArgs args)
    {
        if (!ready || updating) return;
        selections[(int)mode] = (Results.SelectedItem as ResultItem)?.Row.Key;
        RefreshDetails();
    }
    private void Refresh()
    {
        if (!ready || closing || updating) return;
        var widths = tableColumns[(int)mode];
        bool showStatus = mode == Backend.Mode.Ip && Backend.HasContinuousResults;
        if (widths.ShowStatus != showStatus)
        {
            widths.ShowStatus = showStatus;
            RebuildHeaders();
            ResizeTable();
        }
        var snapshot = Backend.Results(mode, filters[(int)mode], sort[(int)mode], descending[(int)mode]);
        var key = selections[(int)mode];
        updating = true;
        try
        {
            // Update existing row containers in place when only metadata changes.
            if (ReferenceEquals(snapshot, renderedSnapshot)) { }
            else if (rows.Count == snapshot.Length && rows.Select((r, i) => Equals(r.Row.Key, snapshot[i].Key)).All(equal => equal))
            {
                for (int i = 0; i < snapshot.Length; i++) rows[i].Update(snapshot[i]);
            }
            else
            {
                var old = rows.ToDictionary(item => item.Row.Key);
                var next = snapshot.Select(row =>
                {
                    if (!old.TryGetValue(row.Key, out var item)) return new ResultItem(row, tableColumns[(int)mode]);
                    item.Update(row);
                    return item;
                }).ToArray();
                int common = 0;
                while (common < rows.Count && common < next.Length && ReferenceEquals(rows[common], next[common])) common++;
                if (common == rows.Count)
                {
                    for (int i = common; i < next.Length; i++) rows.Add(next[i]);
                }
                else rows.Replace(next);
            }
            renderedSnapshot = snapshot;
            if (Results.SelectedItem is not ResultItem current || !Equals(current.Row.Key, key))
                Results.SelectedItem = key == null ? null : rows.FirstOrDefault(r => Equals(r.Row.Key, key));
        }
        finally { updating = false; }

        var status = Backend.Progress(mode, rows.Count);
        string nextStatus = status.Text + (status.Running && mode == Backend.Mode.Ip ? $" · {status.Done}/{status.Total}" : "") +
            (notice.Length == 0 ? "" : " · " + notice);
        if (Status.Text != nextStatus) Status.Text = nextStatus;
        UpdateStartButton(status.Running);
        Progress.Visibility = Show(status.Running);
        Progress.IsIndeterminate = mode != Backend.Mode.Ip;
        Progress.Maximum = Math.Max(1, status.Total);
        Progress.Value = Math.Clamp(status.Done, 0, Progress.Maximum);
        RefreshDetails();
    }

    private void UpdateStartButton(bool running)
    {
        string action = running ? L("Stopp", "Stop") : mode switch
        {
            Backend.Mode.Ip => L("Scan starten", "Start scan"),
            Backend.Mode.Mdns => L("Suche starten", "Start discovery"),
            _ => L("Mitschnitt starten", "Start capture")
        };
        string glyph = running ? "\uE71A" : "\uE768";
        if (StartIcon.Glyph != glyph) StartIcon.Glyph = glyph;
        if (AutomationProperties.GetName(StartButton) == action) return;
        AutomationProperties.SetName(StartButton, action);
        ToolTipService.SetToolTip(StartButton, action);
    }

    private void RefreshDetails()
    {
        if (!Backend.HasStartedRun(mode))
        {
            DetailTitle.Text = "";
            RenderDetails([]);
            return;
        }

        var key = (Results.SelectedItem as ResultItem)?.Row.Key;
        if (!Equals(displayedDetailKey, key) || displayedDetailMode != mode)
        {
            displayedDetailKey = key;
            displayedDetailMode = mode;
            DetailScroll.ChangeView(null, 0, null, true);
        }
        if (Results.SelectedItem is ResultItem item)
        {
            var row = item.Row;
            string title = Backend.DetailHeading(mode, row);
            if (DetailTitle.Text != title) DetailTitle.Text = title;
            RenderDetails(Backend.Details(mode, row));
        }
        else
        {
            DetailTitle.Text = L("Details", "Details");
            RenderDetails([new Backend.DetailField("", rows.Count == 0 ? L("Keine Ergebnisse.", "No results.") :
                L("Wähle eine Zeile aus.", "Select a row."))]);
        }
    }

    private void RenderDetails(Backend.DetailField[] fields)
    {
        int columns = detailOnRight ? 1 : Math.Clamp((int)(DetailScroll.ActualWidth / 250), 1, 3);
        if (columns == renderedDetailColumns && fields.SequenceEqual(renderedFields)) return;
        renderedFields = fields;
        renderedDetailColumns = columns;
        DetailFields.Children.Clear();
        DetailFields.ColumnDefinitions.Clear();
        DetailFields.RowDefinitions.Clear();
        for (int i = 0; i < columns; i++)
            DetailFields.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        for (int i = 0; i < fields.Length; i++)
        {
            if (i % columns == 0) DetailFields.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            var field = fields[i];
            var text = new TextBlock { TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true };
            if (field.Name.Length > 0)
                text.Inlines.Add(new Microsoft.UI.Xaml.Documents.Run
                {
                    Text = field.Name + ":",
                    FontWeight = Microsoft.UI.Text.FontWeights.Bold
                });
            if (field.Name.Length > 0) text.Inlines.Add(new Microsoft.UI.Xaml.Documents.LineBreak());
            AddDetailValue(text, field);
            Grid.SetColumn(text, i % columns);
            Grid.SetRow(text, i / columns);
            DetailFields.Children.Add(text);
        }
    }

    private void AddDetailValue(TextBlock text, Backend.DetailField field)
    {
        if (field.Link == Backend.DetailLink.None)
        {
            text.Inlines.Add(new Microsoft.UI.Xaml.Documents.Run { Text = field.Value });
            return;
        }

        if (field.Link is not (Backend.DetailLink.Web or Backend.DetailLink.Share))
        {
            AddDetailLink(text, field.Value, field.Link, field.Target, field.Port);
            return;
        }

        var targets = field.Target.Split('\n');
        var lines = field.Value.Split('\n');
        for (int i = 0; i < lines.Length; i++)
        {
            if (i > 0) text.Inlines.Add(new Microsoft.UI.Xaml.Documents.LineBreak());
            string line = lines[i];
            bool Matches(string value) => line == value || line.StartsWith(value + " - ", StringComparison.Ordinal);
            string target = field.Link == Backend.DetailLink.Share
                ? i < targets.Length && Matches(targets[i]) ? targets[i] : null
                : targets.FirstOrDefault(Matches);
            if (target == null) text.Inlines.Add(new Microsoft.UI.Xaml.Documents.Run { Text = line });
            else
            {
                AddDetailLink(text, target, field.Link, target, 0);
                if (line.Length > target.Length)
                    text.Inlines.Add(new Microsoft.UI.Xaml.Documents.Run { Text = line[target.Length..] });
            }
        }
    }

    private void AddDetailLink(TextBlock text, string label, Backend.DetailLink kind, string target, int port)
    {
        var link = new Microsoft.UI.Xaml.Documents.Hyperlink();
        link.Inlines.Add(new Microsoft.UI.Xaml.Documents.Run { Text = label });
        link.Click += async (_, _) => await Perform(() => OpenDetailLink(kind, target, port));
        text.Inlines.Add(link);
    }

    private async Task OpenDetailLink(Backend.DetailLink kind, string target, int port)
    {
        string system = Environment.GetFolderPath(Environment.SpecialFolder.System);
        switch (kind)
        {
            case Backend.DetailLink.Web:
                OpenWithWindows(target);
                break;
            case Backend.DetailLink.Share:
                StartClient(Path.Combine(Directory.GetParent(system).FullName, "explorer.exe"), target);
                break;
            case Backend.DetailLink.Rdp:
                StartClient(Path.Combine(system, "mstsc.exe"), "/v:" + target);
                break;
            case Backend.DetailLink.Ssh:
                var input = new TextBox
                {
                    Header = L("Benutzername", "Username"),
                    MaxLength = 256,
                    IsSpellCheckEnabled = false
                };
                var dialog = Dialog("SSH · " + target, input, L("Verbinden", "Connect"));
                dialog.IsPrimaryButtonEnabled = false;
                input.TextChanged += (_, _) => dialog.IsPrimaryButtonEnabled = IsSshUserName(input.Text.Trim());
                if (await ShowDialog(dialog) != ContentDialogResult.Primary || closing) return;
                StartClient(Path.Combine(system, "OpenSSH", "ssh.exe"), "-l", input.Text.Trim(), "-p",
                    port.ToString(System.Globalization.CultureInfo.InvariantCulture), target);
                break;
            case Backend.DetailLink.Telnet:
                string telnet = Path.Combine(system, "telnet.exe");
                if (File.Exists(telnet)) StartClient(telnet, target, port.ToString(System.Globalization.CultureInfo.InvariantCulture));
                else OpenWithWindows(new UriBuilder("telnet", target, port).Uri.AbsoluteUri);
                break;
            case Backend.DetailLink.Ftp:
                string ftp = Path.Combine(system, "ftp.exe");
                if (port == 21 && File.Exists(ftp)) StartClient(ftp, target);
                else OpenWithWindows(new UriBuilder("ftp", target, port).Uri.AbsoluteUri);
                break;
        }
    }

    private static bool IsSshUserName(string value) =>
        value.Length > 0 && value.Any(char.IsLetterOrDigit) &&
        value.All(c => char.IsLetterOrDigit(c) || c is '.' or '_' or '-' or '\\' or '@');

    private void StartClient(string executable, params string[] arguments)
    {
        if (!File.Exists(executable))
            throw new InvalidOperationException(L("Windows-Client nicht installiert: ", "Windows client not installed: ") + Path.GetFileName(executable));
        var info = new System.Diagnostics.ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            WorkingDirectory = Environment.GetFolderPath(Environment.SpecialFolder.System)
        };
        foreach (var argument in arguments) info.ArgumentList.Add(argument);
        using var process = System.Diagnostics.Process.Start(info);
    }

    private static void OpenWithWindows(string uri)
    {
        using var process = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(uri) { UseShellExecute = true });
    }

    private async Task<ContentDialogResult> ShowDialog(ContentDialog dialog)
    {
        if (closing) return ContentDialogResult.None;
        openDialog = dialog;
        try { return await dialog.ShowAsync(); }
        finally { openDialog = null; }
    }

    private ContentDialog Dialog(string title, object content, string primary = "") => new()
    {
        Title = title, XamlRoot = Root.XamlRoot, Content = content, PrimaryButtonText = primary,
        CloseButtonText = primary.Length == 0 ? L("Schließen", "Close") : L("Abbrechen", "Cancel"),
        DefaultButton = primary.Length == 0 ? ContentDialogButton.Close : ContentDialogButton.Primary
    };

    private async void ExportClicked(object sender, RoutedEventArgs args) => await Perform(Export);

    private async Task Export()
    {
        var exportMode = mode;
        var directory = global::KubScan.App.ExportDirectory;
        // The picker can only open an existing folder. If the configured folder
        // is unavailable, Windows lets the user choose another one.
        try { await Task.Run(() => Directory.CreateDirectory(directory)); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        if (closing) return;

        var picker = new Microsoft.Windows.Storage.Pickers.FileSavePicker(AppWindow.Id)
        {
            SuggestedFolder = directory,
            SuggestedFileName = Path.GetFileNameWithoutExtension(Backend.ExportName(true, exportMode)),
            ShowOverwritePrompt = true
        };
        picker.FileTypeChoices.Add(L("CSV-Datei", "CSV file"), [".csv"]);
        picker.FileTypeChoices.Add(L("Textdatei", "Text file"), [".txt"]);
        var result = await picker.PickSaveFileAsync();
        if (result == null || closing) return;

        var path = result.Path;
        await Task.Run(() => Backend.ExportToPath(path, exportMode));
        notice = L("Gespeichert: ", "Saved: ") + path;
    }

    private Task CopySelectedColumn()
    {
        if (Results.SelectedItem is ResultItem item)
            CopyCell(item.Row.Cells[sort[(int)mode]]);
        return Task.CompletedTask;
    }

    private void CopyCell(string value)
    {
        var data = new DataPackage();
        data.SetText(value ?? "");
        Clipboard.SetContent(data);
        Clipboard.Flush();
        notice = L("Kopiert", "Copied");
    }

    private void ResultRightTapped(object sender, RightTappedRoutedEventArgs args)
    {
        if (!ready || busy || closing ||
            sender is not Grid row || row.DataContext is not ResultItem item) return;

        var position = args.GetPosition(row);
        int column = ColumnAt(row, position.X, item.Row.Cells.Length);
        if (column < 0 && mode != Backend.Mode.Ip) return;

        Results.SelectedItem = item;
        args.Handled = true;
        CreateResultMenu(item, column).ShowAt(row, position);
    }

    private static int ColumnAt(Grid row, double x, int count)
    {
        x -= row.ColumnDefinitions[0].ActualWidth;
        if (x < 0) return -1;
        for (int column = 0; column < count; column++)
        {
            double width = row.ColumnDefinitions[column + 1].ActualWidth;
            if (x < width) return column;
            x -= width;
        }
        return -1;
    }

    private MenuFlyout CreateResultMenu(ResultItem item, int column)
    {
        var menu = new MenuFlyout();
        if (column >= 0)
        {
            var value = item.Row.Cells[column];
            var copy = new MenuFlyoutItem { Text = L("Kopieren", "Copy"), Icon = new SymbolIcon(Symbol.Copy) };
            copy.Click += async (_, _) => await Perform(() =>
            {
                CopyCell(value);
                return Task.CompletedTask;
            });
            menu.Items.Add(copy);
        }
        if (mode != Backend.Mode.Ip) return menu;

        void Add(string label, string operation, string title, Symbol icon)
        {
            var entry = new MenuFlyoutItem { Text = label, Icon = new SymbolIcon(icon) };
            entry.Click += async (_, _) => await Perform(() => HostAction(operation, title, item));
            menu.Items.Add(entry);
        }
        if (menu.Items.Count > 0) menu.Items.Add(new MenuFlyoutSeparator());
        Add(L("TCP-Portscan vollständig", "Full TCP port scan"), "full", "TCP 1–65535", Symbol.Scan);
        Add(L("TCP-Portscan manuell", "Custom TCP port scan"), "tcp", "TCP", Symbol.Edit);
        Add(L("UDP-Portscan", "UDP port scan"), "udp", "UDP", Symbol.Find);
        Add(L("Dauerping", "Continuous ping"), "ping", L("Dauerping", "Continuous ping"), Symbol.Sync);
        Add(L("Betriebssystem vermuten", "Estimate operating system"), "os", L("Betriebssystem", "Operating system"), Symbol.AllApps);
        var connections = Backend.ContextConnections(item.Row).ToArray();
        if (connections.Length > 0) menu.Items.Add(new MenuFlyoutSeparator());
        foreach (var connection in connections)
        {
            var entry = new MenuFlyoutItem
            {
                Text = connection.Label,
                Icon = connection.Link switch
                {
                    Backend.DetailLink.Rdp => new SymbolIcon(Symbol.Remote),
                    Backend.DetailLink.Ssh => new FontIcon { Glyph = "\uE756" },
                    Backend.DetailLink.Web => new SymbolIcon(Symbol.Globe),
                    _ => new SymbolIcon(Symbol.Link)
                }
            };
            entry.Click += async (_, _) => await Perform(() =>
                OpenDetailLink(connection.Link, connection.Target, connection.Port));
            menu.Items.Add(entry);
        }
        return menu;
    }

    private async Task HostAction(string operation, string title, ResultItem item)
    {
        string input = operation == "full" ? "1-65535" : "";
        if (operation is "tcp" or "udp")
        {
            var box = new TextBox { Header = L("Ports (1–65535)", "Ports (1–65535)"),
                Text = operation == "udp" ? "53,123,137,161,500,1900,4500,5353" : "",
                PlaceholderText = "22,80,443,8000-8100" };
            if (await ShowDialog(Dialog(title, box, L("Starten", "Start"))) != ContentDialogResult.Primary) return;
            input = box.Text;
        }
        if (closing) return;
        await using var tool = new Backend.HostTool(item.Row, operation, input);
        activeTool = tool;
        try { await ShowTool(title + " · " + item.Row.Cells[0], tool.Snapshot, tool.Cancel, operation == "ping" ? tool : null,
            showPortProgress: operation is "full" or "tcp" or "udp"); }
        finally { activeTool = null; }
    }

    private async Task OuiUpdate()
    {
        using var cancellation = new CancellationTokenSource();
        Backend.StartOuiUpdate(cancellation.Token);
        try { await ShowTool(L("OUI-Update", "OUI update"), Backend.OuiStatus, cancellation.Cancel); }
        finally
        {
            cancellation.Cancel();
            await Backend.FinishOuiUpdateAsync();
        }
    }

    private async Task ShowTool(string title, Func<Backend.ToolStatus> snapshot, Action cancel = null,
        Backend.HostTool ping = null, bool showPortProgress = false)
    {
        var progress = new ProgressBar { VerticalAlignment = VerticalAlignment.Center };
        var text = new TextBlock { TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true };
        var scroll = new ScrollViewer { Content = text, Height = 235 };
        var panel = new StackPanel { Spacing = 10 };
        var counter = new TextBlock { VerticalAlignment = VerticalAlignment.Center };
        if (showPortProgress)
        {
            var progressRow = new Grid { ColumnSpacing = 10 };
            progressRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            progressRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            Grid.SetColumn(counter, 1);
            progressRow.Children.Add(progress);
            progressRow.Children.Add(counter);
            panel.Children.Add(scroll);
            panel.Children.Add(progressRow);
        }
        else
        {
            panel.Children.Add(progress);
            panel.Children.Add(scroll);
        }

        var dialog = Dialog(title, panel);
        if (cancel != null)
        {
            dialog.SecondaryButtonClick += async (_, args) =>
            {
                args.Cancel = true;
                if (ping == null) cancel();
                else
                {
                    dialog.IsSecondaryButtonEnabled = false;
                    try { await ping.TogglePingAsync(); }
                    catch (Exception error) { notice = error.Message; }
                    finally { dialog.IsSecondaryButtonEnabled = true; }
                }
            };
        }

        var clock = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(300) };
        void Render()
        {
            if (closing) return;
            var state = snapshot();
            progress.Visibility = Show(showPortProgress || state.Running);
            progress.IsIndeterminate = !showPortProgress && state.Total <= 0;
            progress.Maximum = Math.Max(1, state.Total);
            int checkedPorts = Math.Clamp(state.Done, 0, Math.Max(0, state.Total));
            progress.Value = checkedPorts;
            if (showPortProgress)
            {
                int percentage = state.Total > 0 ? (int)(100L * checkedPorts / state.Total) : 0;
                string caption = $"{percentage}% ({checkedPorts} / {state.Total})";
                if (counter.Text != caption) counter.Text = caption;
            }
            if (text.Text != state.Text) text.Text = state.Text;
            if (cancel != null)
            {
                string caption = ping != null
                    ? ping.Paused ? L("Fortsetzen", "Resume") : L("Pausieren", "Pause")
                    : state.Running ? L("Abbrechen", "Cancel") : "";
                if (dialog.SecondaryButtonText != caption) dialog.SecondaryButtonText = caption;
            }
        }
        clock.Tick += (_, _) => Render();
        Render();
        clock.Start();
        try { await ShowDialog(dialog); }
        finally { clock.Stop(); }
    }

    private async Task ShowHelp()
    {
        string help = L(
            """
            IP findet Geräte im angegebenen Netz. Gib ein Subnetz wie 192.168.1.0/24, eine einzelne IPv4-Adresse mit anschließender Präfixauswahl oder einen Bereich wie 192.168.1.10-25 ein. Der Pfeil im Feld öffnet den Verlauf mit häufig und zuletzt verwendeten Bereichen. Mit dem Kreispfeil aktivierst du den Dauerscan, der den Bereich wiederholt prüft und Änderungen markiert.

            mDNS findet lokal angekündigte Dienste. ARP zeigt ARP-Anfragen auf dem gewählten Netzwerkadapter. Der ARP-Mitschnitt braucht unter Windows Administratorrechte.

            Die Lupe filtert die Ergebnisliste. Ein Klick auf einen Spaltenkopf sortiert, ein weiterer kehrt die Reihenfolge um. Wähle eine Zeile, um Details zu sehen. Mit dem Pfeil im Detailbereich wechselst du zwischen der Ansicht rechts und unter der Tabelle.

            Per Rechtsklick kannst du Zellen kopieren. Bei IP-Ergebnissen kannst du außerdem TCP- und UDP-Ports prüfen, einen Dauerping starten, das Betriebssystem einschätzen oder erkannte Verbindungen öffnen. Der Export speichert IP- und mDNS-Ergebnisse als CSV oder Textdatei.

            Im Menü ⋯ findest du Sprache und Design sowie je nach Ansicht die Aktualisierung der Herstellerdaten oder das Zurücksetzen des ARP-Mitschnitts.

            F1 öffnet die Hilfe, F2 startet oder stoppt, F3 schaltet in der IP-Ansicht den Dauerscan um, F7 öffnet die Suche und F9 stoppt. Im Subnetzfeld startet auch Enter den Scan.
            """,
            """
            IP finds devices on the specified network. Enter a subnet such as 192.168.1.0/24, a single IPv4 address and then select a prefix, or a range such as 192.168.1.10-25. The arrow in the field opens your frequently and recently used ranges. Use the circular arrow to enable continuous scanning, which checks the range repeatedly and highlights changes.

            mDNS discovers services advertised on the local network. ARP shows ARP requests on the selected network adapter. On Windows, ARP capture requires administrator rights.

            Use the search button to filter results. Click a column header to sort and click it again to reverse the order. Select a row to view its details. The arrow in the details pane moves it between the right side and below the table.

            Right-click to copy a cell. For IP results, you can also scan TCP and UDP ports, start a continuous ping, estimate the operating system, or open detected connections. Export saves IP and mDNS results as CSV or plain text.

            The ⋯ menu contains language and theme settings. Depending on the view, it also lets you update vendor data or reset the ARP capture.

            F1 opens help, F2 starts or stops, F3 toggles continuous scanning in IP view, F7 opens search, and F9 stops. Enter also starts a scan from the subnet field.
            """);
        var scroll = new ScrollViewer
        {
            MaxHeight = 420,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            Content = new TextBlock { Text = help, TextWrapping = TextWrapping.Wrap }
        };
        await ShowDialog(Dialog(L("KubScan-Hilfe", "KubScan help"), scroll));
    }

    private void RestoreTheme()
    {
        var theme = ElementTheme.Default;
        try
        {
            if (File.Exists(ThemePath))
            {
                theme = File.ReadAllText(ThemePath).Trim() switch
                {
                    "Light" or "Fluent" => ElementTheme.Light,
                    "Dark" => ElementTheme.Dark,
                    _ => ElementTheme.Default
                };
            }
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        ApplyTheme(theme);
    }

    private static void SavePreference(string path, string value)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path));
        string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllText(temporary, value);
            File.Move(temporary, path, true);
        }
        finally { File.Delete(temporary); }
    }

    private void ApplyTheme(ElementTheme theme)
    {
        WindowLayout.RequestedTheme = theme;
        AppWindow.TitleBar.PreferredTheme = theme switch
        {
            ElementTheme.Light => TitleBarTheme.Light,
            ElementTheme.Dark => TitleBarTheme.Dark,
            _ => TitleBarTheme.UseDefaultAppMode
        };
    }

    private async void Closing(AppWindow sender, AppWindowClosingEventArgs args)
    {
        if (allowClose) return;
        args.Cancel = true;
        if (closing) return;
        closing = true;
        timer.Stop();
        activeTool?.Cancel();
        openDialog?.Hide();
        try
        {
            while (busy) await Task.Delay(20);
            await Backend.ShutdownAsync();
        }
        finally { allowClose = true; Close(); }
    }
}

internal sealed class ResultCollection : ObservableCollection<ResultItem>
{
    public void Replace(IEnumerable<ResultItem> items)
    {
        Items.Clear();
        foreach (var item in items) Items.Add(item);
        OnPropertyChanged(new PropertyChangedEventArgs(nameof(Count)));
        OnPropertyChanged(new PropertyChangedEventArgs("Item[]"));
        OnCollectionChanged(new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset));
    }
}

public sealed class ResultItem : INotifyPropertyChanged
{
    public ResultItem(Backend.Row row, TableColumnWidths columns)
    {
        Row = row;
        Columns = columns;
    }

    public TableColumnWidths Columns { get; }
    public Backend.Row Row { get; private set; }
    private static readonly Brush InitialBrush = new SolidColorBrush(Windows.UI.Color.FromArgb(255, 128, 128, 128));
    private static readonly Brush AddedBrush = new SolidColorBrush(Windows.UI.Color.FromArgb(255, 33, 148, 66));
    private static readonly Brush MissingBrush = new SolidColorBrush(Windows.UI.Color.FromArgb(255, 210, 48, 56));

    public Brush StatusBrush => Row.Presence switch { < 0 => MissingBrush, > 0 => AddedBrush, _ => InitialBrush };
    public string StatusText => Row.Presence switch
    {
        < 0 => Backend.Text("Fehlt", "Missing"),
        > 0 => Backend.Text("Hinzugekommen oder wieder erreichbar", "Added or reachable again"),
        _ => Backend.Text("Seit dem ersten Durchlauf", "Present since the first pass")
    };

    public string First => Row.Cells[0];
    public string Second => Row.Cells[1];
    public string Third => Row.Cells[2];
    public string Fourth => Row.Cells[3];
    public string Fifth => Row.Cells.Length == 5 ? Row.Cells[4] : "";
    public event PropertyChangedEventHandler PropertyChanged;

    public void Update(Backend.Row row)
    {
        bool changed = Row.Presence != row.Presence || !Row.Cells.SequenceEqual(row.Cells);
        Row = row;
        if (changed) PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(string.Empty));
    }
}

public sealed class TableColumnWidths(int count) : INotifyPropertyChanged
{
    private static readonly double[] Weights = [1, 1.5, 1.15, 1.4, 0.65];
    private readonly double?[] pixels = new double?[count];

    public GridLength this[int index] => index >= count ? new GridLength(0) :
        pixels[index] is double width ? new GridLength(width) : new GridLength(Weights[index], GridUnitType.Star);

    public GridLength First => this[0];
    public GridLength Second => this[1];
    public GridLength Third => this[2];
    public GridLength Fourth => this[3];
    public GridLength Fifth => this[4];
    private bool showStatus;
    public bool ShowStatus
    {
        get => showStatus;
        internal set
        {
            if (showStatus == value) return;
            showStatus = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(StatusWidth)));
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(StatusVisibility)));
        }
    }
    public GridLength StatusWidth => new(ShowStatus ? 72 : 0);
    public Visibility StatusVisibility => ShowStatus ? Visibility.Visible : Visibility.Collapsed;
    internal double MinimumTableWidth => 36 + StatusWidth.Value + pixels.Sum(width => width ?? 88);

    public event PropertyChangedEventHandler PropertyChanged;

    internal void Resize(int index, double width)
    {
        pixels[index] = Math.Clamp(width, 56, 2400);
        string[] properties = [nameof(First), nameof(Second), nameof(Third), nameof(Fourth), nameof(Fifth)];
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(properties[index]));
    }
}
