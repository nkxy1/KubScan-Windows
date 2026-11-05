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

Ohne Parameter öffnet `KubScan.WinUI.exe` die WinUI-Oberfläche. Mit `--tui` läuft die bisherige Terminaloberfläche in derselben Terminalsitzung. Die Shell wartet, bis du KubScan mit F10 beendest. Für automatische Scans stehen die bisherigen Kommandozeilenargumente zur Verfügung.

```powershell
.\dist\win-x64\KubScan.WinUI.exe
.\dist\win-x64\KubScan.WinUI.exe --tui
.\dist\win-x64\KubScan.WinUI.exe --tui -Subnet 192.168.1.0/24
.\dist\win-x64\KubScan.WinUI.exe scan 127.0.0.1/32 -csv
```

Ab Windows 11 24H2 oder Windows Server 2025 startet die EXE aus dem Explorer ohne zusätzliches Konsolenfenster. Ältere Windows-Versionen können beim Explorer-Start eine Konsole öffnen.

## Desktop-Tests

```powershell
dotnet run --project .\tests\Desktop\Desktop.csproj -c Release
```

Für den ARP-Mitschnitt sind Administratorrechte und eine Windows-Version mit aktueller PktMon-Streaming-API erforderlich.

## Portable Windows-EXE

```powershell
.\packaging\Publish-Portable.ps1
```

Die Datei `dist/portable-win-x64/KubScan.exe` enthält die x64-Laufzeit,
die OUI-Datenbank und die WinUI-Oberfläche. Zum Weitergeben genügt diese Datei.
Beim ersten GUI-Start entpackt KubScan die WinUI-Dateien nach
`%LOCALAPPDATA%\KubScan\Portable` und verwendet sie bei weiteren Starts wieder.

Beim Aufruf aus einem interaktiven Terminal öffnet sich ohne Argumente die TUI.
Mit `--tui` lässt sie sich explizit auswählen. KubScan nutzt dieselbe Konsole,
und PowerShell bzw. CMD wartet bis zum Beenden der TUI mit F10. Scanargumente
gehen direkt an die Kommandozeile.

Ein Doppelklick im Explorer öffnet WinUI ab Windows-Build 17763
(Windows Server 2019 mit Desktopdarstellung). Ab Windows 11 24H2 bzw.
Windows Server 2025 startet die GUI ohne Konsolenfenster. Auf älteren Systemen
kann Windows kurz eine Konsole öffnen, die KubScan vor dem Laden der GUI freigibt.
Windows Server 2016 und Server Core verwenden die Terminaloberfläche.
Der ARP-Mitschnitt setzt weiterhin eine Windows-Version mit PktMon-Streaming voraus.

## Startperformance

Release-Veröffentlichungen der GUI verwenden ReadyToRun, damit weniger Code beim Start
JIT-kompiliert werden muss. CLI und TUI initialisieren die native Windows-App-Laufzeit
nicht. Die OUI-Datenbank wird erst bei der ersten Herstellerabfrage eines geeigneten
MAC-Präfixes geladen; parallele Abfragen teilen sich denselben vollständig geladenen
Datenbestand. OUI-Updates ersetzen ihn weiterhin atomar. Die GUI bereitet Einstellungen
und Netzwerkvorbelegung parallel im Hintergrund vor. Unveränderte Einstellungen werden
beim Start nicht erneut geschrieben. Portable Builds komprimieren das WinUI-Paket.
Die portable EXE nutzt zusätzlich die Bundle-Kompression für die eingebettete
.NET-Laufzeit und den Programmcode.
Nach abgeschlossenen IP-Scans verwendet die GUI unveränderte Ergebnislisten wieder,
statt sie bei jedem Timer-Tick neu zu sortieren und aufzubauen. Neue Scans,
OUI-Updates, Filter, Sortierung und Sprachwechsel werden dabei berücksichtigt.

Startmessungen für zwei veröffentlichte Versionen lassen sich mit demselben Skript
wiederholen:

```powershell
.\tests\Measure-Startup.ps1 -Executable .\dist\win-x64\KubScan.WinUI.exe
```

`FirstOutputMs` misst die Zeit bis zur ersten Konsolenausgabe, `TotalMs` zusätzlich
den vollständigen Loopbackscan und das Prozessende. Den ersten Lauf getrennt von
Folgeläufen beurteilen; das Skript leert keine Betriebssystem-Caches. Für vergleichbare
Ergebnisse denselben Startort verwenden. Beim Start von einer Netzwerkfreigabe fallen
zusätzlich Zugriffe für .NET- und WinUI-Bibliotheken an; bei Bedarf den gesamten
Veröffentlichungsordner auf eine lokale Festplatte kopieren.

Messung vom 05.11.2026 auf derselben Windows-Maschine und Netzwerkfreigabe:
Median von vier Folgeläufen nach jeweils einem ersten Lauf, v.1.0.82 gegen v.1.0.83.
Beim oben verwendeten Loopbackscan sank die Zeit bis zur ersten Ausgabe von
256,6 auf 184,5 ms (28 %); einschließlich Scan und Prozessende von 642,1 auf
560,2 ms (13 %). Das sind CLI-Messungen, keine garantierten GUI- oder Kaltstartzeiten.
