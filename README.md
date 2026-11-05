# KubScan für Windows

KubScan ist eine WinUI-3-Anwendung für IPv4-Scans, die Suche nach lokalen mDNS-Diensten und den Mitschnitt von ARP-Anfragen. Die Programmversion steht in `App.Version` in `KubScan.cs`. Die Hilfe im Programm öffnet sich mit F1.

## Build und Veröffentlichung

Voraussetzungen sind Windows x64, das .NET SDK 10 und beim ersten Build Zugriff auf NuGet. Das Projekt verwendet Windows App SDK 2.6.5. Die OUI-Datenbank zur Herstellererkennung ist im Quellcode-Repository enthalten und wird eingebettet.

Im Repository-Ordner ausführen:

```powershell
dotnet publish .\WinUI\KubScan.WinUI.csproj -c Release -o .\dist\win-x64
```

Danach `dist\win-x64\KubScan.WinUI.exe` starten. Den gesamten Ausgabeordner zusammenhalten, da er auch die .NET- und Windows-App-SDK-Laufzeiten enthält. Sollte das Manifestwerkzeug den Netzwerkpfad ablehnen, den Build aus einer lokalen Arbeitskopie starten.

## WinUI, Terminal und Kommandozeile starten

Ohne Parameter öffnet `KubScan.WinUI.exe` die WinUI-Oberfläche. Starte die bisherige Terminaloberfläche mit `KubScan.cmd --tui`. Sie verwendet dasselbe Terminal und gibt es bei F10 wieder frei.

```powershell
.\dist\win-x64\KubScan.WinUI.exe
.\dist\win-x64\KubScan.cmd --tui
.\dist\win-x64\KubScan.cmd --tui -Subnet 192.168.1.0/24
```

`KubScan.cmd` reicht die Argumente an die EXE weiter und wartet auf deren Ende. Der direkte Aufruf der GUI-EXE kann in einer interaktiven Shell sofort zur Eingabeaufforderung zurückkehren. Verwende für die TUI den Starter oder in PowerShell `Start-Process -Wait -NoNewWindow`, damit die Shell währenddessen keine Eingaben liest.

Für automatische Scans akzeptiert die EXE weiterhin die bisherigen Kommandozeilenargumente. In PowerShell wartet `Start-Process -Wait -NoNewWindow` auf den Scan und gibt seine Ausgabe im Terminal aus. Mit `-PassThru` steht außerdem der Exitcode zur Verfügung.

```powershell
Start-Process .\dist\win-x64\KubScan.WinUI.exe -Wait -NoNewWindow -ArgumentList 'scan','127.0.0.1/32','-csv'
```

## Desktop-Tests

```powershell
dotnet run --project .\tests\Desktop\Desktop.csproj -c Release
```

Für den ARP-Mitschnitt sind Administratorrechte und eine Windows-Version mit aktueller PktMon-Streaming-API erforderlich.
