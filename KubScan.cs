using System;
using System.Linq;
using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
namespace KubScan {
public class Host {
 public string IP, DNS="Wird ermittelt ...", Ports="Werden geprueft ...";
 public string NameSource="Wird ermittelt ...";
 public volatile string WebServers,SmbShares,UdpPorts;
 public volatile string[] WebLinks,SmbPaths;
 public string ServicePorts;
 public int PresenceChange;
 public long ContinuousOrder;
 public int MissedRounds;
 public bool Returned;
 public string Vendor="Wird ermittelt ..."; public string MAC="Wird ermittelt ..."; public long Ping; public int ReplyTtl;
}
public static partial class App {
 static readonly bool IsWindows=Environment.OSVersion.Platform==PlatformID.Win32NT;
 static DateTime BerlinNow() { return TimeZoneInfo.ConvertTimeBySystemTimeZoneId(DateTime.UtcNow,IsWindows?"W. Europe Standard Time":"Europe/Berlin"); }
 // Linux desktop clipboard providers receive text on stdin, never through a shell.
 static void LinuxClipboard(string value) {
  string[] commands=string.IsNullOrEmpty(Environment.GetEnvironmentVariable("WAYLAND_DISPLAY"))?new[]{"xclip","xsel"}:new[]{"wl-copy","xclip","xsel"};
  foreach(string command in commands) {
   var info=new System.Diagnostics.ProcessStartInfo(command,command=="xclip"?"-selection clipboard":command=="xsel"?"--clipboard --input":"");
   info.UseShellExecute=false; info.RedirectStandardInput=true; info.RedirectStandardError=true; info.CreateNoWindow=true;
   try { using(var process=System.Diagnostics.Process.Start(info)) {
    process.StandardInput.Write(value); process.StandardInput.Close();
    if(!process.WaitForExit(2000)) { process.Kill(); continue; }
    if(process.ExitCode==0) return;
   } } catch(System.ComponentModel.Win32Exception) {} catch(System.IO.IOException) {}
  }
  throw new InvalidOperationException(English?"Clipboard unavailable: install wl-clipboard (Wayland) or xclip/xsel (X11).":"Zwischenablage nicht verfuegbar: wl-clipboard (Wayland) oder xclip/xsel (X11) installieren.");
 }
 // Ping/TCP discovery populates the kernel neighbour cache without raw-socket privileges.
 static string LinuxMac(string ip,string device) {
  try {
   foreach(string line in System.IO.File.ReadAllLines("/proc/net/arp").Skip(1)) {
    string[] fields=line.Split((char[])null,StringSplitOptions.RemoveEmptyEntries);
    if(fields.Length>=6 && fields[0]==ip && fields[5]==device && (Convert.ToInt32(fields[2],16)&2)!=0 && System.Text.RegularExpressions.Regex.IsMatch(fields[3],"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$") && fields[3]!="00:00:00:00:00:00") return fields[3].ToUpperInvariant();
   }
  } catch(System.IO.IOException) {} catch(UnauthorizedAccessException) {}
  return null;
 }
 // .NET decodes terminal function/navigation keys; only SGR mouse reports need additional parsing.
 static readonly System.Collections.Generic.Queue<ConsoleKeyInfo> linuxPendingKeys=new System.Collections.Generic.Queue<ConsoleKeyInfo>();
 static bool TryReadLinuxKey(out ConsoleKeyInfo key) {
  key=default(ConsoleKeyInfo);
  if(linuxPendingKeys.Count>0) { key=linuxPendingKeys.Dequeue(); return true; }
  while(Console.KeyAvailable) {
   key=Console.ReadKey(true);
   if(key.Key!=ConsoleKey.Escape) return true;
   var report=new System.Text.StringBuilder();
   var consumed=new System.Collections.Generic.List<ConsoleKeyInfo>();
   var timer=System.Diagnostics.Stopwatch.StartNew();
   bool mouse=false;
   while(consumed.Count<64 && timer.ElapsedMilliseconds<50) {
    if(!Console.KeyAvailable) { Thread.Sleep(1); continue; }
    var next=Console.ReadKey(true); consumed.Add(next); report.Append(next.KeyChar);
    if(consumed.Count==1 && next.KeyChar!='[') break;
    if(consumed.Count==2) { if(next.KeyChar!='<') break; mouse=true; }
    if(mouse && (next.KeyChar=='M' || next.KeyChar=='m')) break;
   }
   if(!mouse) { foreach(var item in consumed) linuxPendingKeys.Enqueue(item); return true; }
   var match=System.Text.RegularExpressions.Regex.Match(report.ToString(),@"^\[<(\d{1,5});(\d{1,5});(\d{1,5})([Mm])$");
   if(!match.Success) continue;
   int button=int.Parse(match.Groups[1].Value);
   if((button&67)!=0 || match.Groups[4].Value!="M") continue;
   int index=MenuHitTest(int.Parse(match.Groups[2].Value)-1,int.Parse(match.Groups[3].Value)-1,Console.WindowWidth-1,Console.WindowHeight);
   if(index<0) continue;
   key=new ConsoleKeyInfo('\0',MenuAction(index),false,false,false); return true;
  }
  return false;
 }
 // Stop reports before shutdown waits; consume the release of the quit-menu click.
 // Otherwise its SGR bytes become input for the calling shell after .NET exits.
 static void StopLinuxMouseInput() {
  Console.Write("\u001b[?1000l\u001b[?1006l");
  Console.Out.Flush();
  linuxPendingKeys.Clear();
  var timer=System.Diagnostics.Stopwatch.StartNew(); long lastInput=0;
  try {
   while(timer.ElapsedMilliseconds<250 && timer.ElapsedMilliseconds-lastInput<60) {
    if(Console.KeyAvailable) { Console.ReadKey(true); lastInput=timer.ElapsedMilliseconds; }
    else Thread.Sleep(2);
   }
  } catch(System.IO.IOException) {} catch(InvalidOperationException) {}
 }
 public const string Version = "v.1.0.79";
 static readonly ConcurrentDictionary<uint,Host> hosts=new ConcurrentDictionary<uint,Host>();
 static CancellationTokenSource cancel;
 static Task scan;
 static int done,total,selected;
 public static bool English=true;
 static readonly System.Collections.Generic.Dictionary<string,string> englishText=new System.Collections.Generic.Dictionary<string,string>(StringComparer.Ordinal) {
  {"Fehler:","Error:"},
  {"Betriebssystem (Vermutung)","Operating system (estimate)"},
  {"Grundlage:","Evidence:"},
  {"Sicherheit: starker Hinweis","Confidence: strong indication"},
  {"Sicherheit: schwacher Hinweis","Confidence: weak indication"},
  {"Sicherheit: unbestimmt","Confidence: undetermined"},
  {"Dienste werden geprueft ...","Checking services ..."},
  {"Pfeile / Bild auf/ab: Details scrollen","Arrows / PgUp/PgDn: scroll details"},
  {"SMB: Zeitlimit erreicht","SMB: timed out"},
  {"SMB: keine OS-Angabe","SMB: no OS information"},
  {"RDP: Zeitlimit erreicht","RDP: timed out"},
  {"RDP: keine OS-Angabe","RDP: no OS information"},
  {"Keine sichere Identifikation.","Not a verified identification."},
  {"Windows (schwacher Hinweis)","Windows (weak indication)"},
  {"Linux/macOS/BSD (schwacher Hinweis)","Linux/macOS/BSD (weak indication)"},
  {"Unbekannt (zu wenige Hinweise)","Unknown (insufficient evidence)"},
  {"Unbekannt (widerspruechliche Hinweise)","Unknown (conflicting evidence)"},
  {"O           Betriebssystem des markierten Hosts abschaetzen","O           Estimate operating system of selected host"},
  {"| Datum:","| Date:"},
  {"| Dienste:","| Services:"},
  {"| Offen:","| Open:"},
  {"│ Antworten:","│ Replies:"},
  {"│ Verlust:","│ Lost:"},
  {"│ CIDR Subnetzmaske","│ CIDR subnet mask"},
  {"TCP-Portscan","TCP port scan"},
  {"HTTPS alternativ","HTTPS alternate"},
  {"Hilfe","Help"},
  {"Dauerping","Continuous ping"},
  {"Suche","Search"},
  {"OUI-Update","OUI update"},
  {"Abbruch","Cancel"},
  {"Ende","Quit"},
  {"Stopp","Stop"},
  {"Standard","Default"},
  {"FEHLER","ERROR"},
  {"Fehler","Error"},
  {"HINWEIS","NOTICE"},
  {"Hersteller","Vendor"},
  {"HERSTELLER","VENDOR"},
  {"DIENST","SERVICE"},
  {"HOSTDETAILS","HOST DETAILS"},
  {"DNS-Name","DNS name"},
  {"Namensquelle","Name source"},
  {"IP-Adresse","IP address"},
  {"IP-Adressen","IP addresses"},
  {"MAC-Adresse","MAC address"},
  {"TCP-Ports","TCP ports"},
  {"Diensttyp","Service type"},
  {"TXT-Metadaten","TXT metadata"},
  {"DNS (Systemresolver)","DNS (system resolver)"},
  {"Wird ermittelt ...","Resolving ..."},
  {"Werden geprueft ...","Checking ..."},
  {"Abgebrochen","Cancelled"},
  {"Abgebrochen.","Cancelled."},
  {"Abbruch laeuft ...","Cancelling ..."},
  {"Keine Antwort","No response"},
  {"Kein Hostname ermittelt","No hostname found"},
  {"Keine im Pruefumfang offen","None open among checked ports"},
  {"Nicht verfuegbar","Unavailable"},
  {"Nicht verfuegbar (Loopback)","Unavailable (loopback)"},
  {"Nicht verfuegbar (ARP/lokales Netz)","Unavailable (ARP/local network)"},
  {"Nicht verfuegbar (keine IPv4-Adresse)","Unavailable (no IPv4 address)"},
  {"Nicht verfuegbar (MAC-Abfrage fehlgeschlagen)","Unavailable (MAC lookup failed)"},
  {"Lokal/privat oder Multicast","Local/private or multicast"},
  {"OUI-Datei fehlt","OUI file missing"},
  {"Unbekannt","Unknown"},
  {"Unbekannt / benutzerdefiniert","Unknown / custom"},
  {"Noch kein Scan gestartet","No scan started yet"},
  {"Subnetz eingeben, Enter startet.","Enter subnet, press Enter to start."},
  {"Subnetz:","Subnet:"},
  {"Suchen:","Search:"},
  {"Suchen","Search"},
  {"Treffer (Esc: loeschen)","matches (Esc: clear)"},
  {"CIDR Subnetzmaske","CIDR subnet mask"},
  {"mDNS: Lokales Netz | M: zurueck zum IP-Scan","mDNS: Local network | M: back to IP scan"},
  {"Dienste:","Services:"},
  {"mDNS-Suche laeuft ...","mDNS scan running ..."},
  {"mDNS-Suche abgeschlossen.","mDNS scan completed."},
  {"mDNS-Suche abgebrochen.","mDNS scan cancelled."},
  {"mDNS-Fehler:","mDNS error:"},
  {"Space / Enter / Esc: zurueck | Hoch/Runter, Bild auf/ab: Details scrollen","Space / Enter / Esc: back | Up/Down, Page Up/Down: scroll details"},
  {"Scan laeuft","Scan running"},
  {"Scan laeuft.","Scan running."},
  {"Scan abgeschlossen","Scan completed"},
  {"Scan abgeschlossen.","Scan completed."},
  {"Scan abgeschlossen. Hosts:","Scan completed. Hosts:"},
  {"Scan abgebrochen.","Scan cancelled."},
  {"Scan laeuft. Esc bricht ab.","Scan running. Esc cancels."},
  {"Noch kein Scan zum Wiederholen vorhanden.","No previous scan to repeat."},
  {"Kein Scanbereich eingegeben.","No scan range entered."},
  {"Kein Eintrag ausgewaehlt.","No entry selected."},
  {"Spaltenwert kopiert.","Column value copied."},
  {"Kein Speicher fuer Zwischenablage.","No memory for clipboard."},
  {"Zwischenablagespeicher nicht verfuegbar.","Clipboard memory unavailable."},
  {"Zwischenablage ist belegt.","Clipboard is busy."},
  {"Zwischenablage konnte nicht geschrieben werden.","Could not write to clipboard."},
  {"Themes benoetigen eine Konsole mit ANSI-Farbunterstuetzung.","Themes require a console with ANSI color support."},
  {"Fenster bitte auf mindestens 90 x","Please resize the window to at least 90 x"},
  {"vergroessern.","characters."},
  {"Interaktive Konsole erforderlich.","An interactive console is required."},
  {"Konsoleneingabe nicht verfuegbar.","Console input unavailable."},
  {"Mauseingabe konnte nicht aktiviert werden.","Could not enable mouse input."},
  {"Ordner:","Folder:"},
  {"Dateiname (Endung fest):","Filename (fixed extension):"},
  {"- gespeichert","- saved"},
  {"Datei erfolgreich gespeichert.","File saved successfully."},
  {"Enter / Esc: Schliessen","Enter / Esc: Close"},
  {"Enter: Speichern │ Esc: Abbrechen","Enter: Save │ Esc: Cancel"},
  {"Ctrl+A: Alles markieren │ Pfeiltasten: Cursor","Ctrl+A: Select all │ Arrow keys: Cursor"},
  {"Bitte einen Dateinamen eingeben.","Please enter a filename."},
  {"Ungueltiger Dateiname (keine Pfade erlaubt).","Invalid filename (paths are not allowed)."},
  {"Reservierter Windows-Dateiname.","Reserved Windows filename."},
  {"Dateiendung muss","File extension must be"},
  {"sein.","."},
  {"Datei existiert bereits. Bitte anderen Namen waehlen.","File already exists. Please choose another name."},
  {"Ports eingeben (Komma, Leerzeichen oder Bereich mit -)","Enter ports (comma, space, or range with -)"},
  {"Offen:","Open:"},
  {"Dienstnamen nach Portnummer; tatsaechlicher Dienst kann abweichen.","Service names are based on port numbers; the actual service may differ."},
  {"Noch keine offenen Ports gefunden.","No open ports found yet."},
  {"Enter: Start | Ctrl+A: Leeren | Esc: Schliessen","Enter: Start | Ctrl+A: Clear | Esc: Close"},
  {"Enter: Abbrechen | Pfeile/Bild auf/ab: Scrollen | Esc: Schliessen","Enter: Cancel | Arrows/Page Up/Down: Scroll | Esc: Close"},
  {"Enter/Esc: Schliessen | Pfeile/Bild auf/ab: Scrollen","Enter/Esc: Close | Arrows/Page Up/Down: Scroll"},
  {"Bitte zuerst einen Host in der Liste auswaehlen.","Please select a host in the list first."},
  {"Bitte mindestens einen Port eingeben.","Please enter at least one port."},
  {"Ports: 1-65535, z.B. 22,80,443,8000-8100","Ports: 1-65535, e.g. 22,80,443,8000-8100"},
  {"Ungueltiger Portbereich:","Invalid port range:"},
  {"Kein Host fuer Dauerping ausgewaehlt.","No host selected for continuous ping."},
  {"Dauerping:","Continuous ping:"},
  {"Gesendet:","Sent:"},
  {"Antworten:","Replies:"},
  {"Verlust:","Lost:"},
  {"Noch keine Antwort","No response yet"},
  {"Antwort:","Reply:"},
  {"Zeitueberschreitung","Request timed out"},
  {"Ping fehlgeschlagen","Ping failed"},
  {"F4: Stoppen │ Enter/Esc: Schliessen","F4: Stop │ Enter/Esc: Close"},
  {"Gestoppt │ F4: Fortsetzen │ Enter/Esc: Schliessen","Stopped │ F4: Resume │ Enter/Esc: Close"},
  {"CIDR auswaehlen:","Select CIDR:"},
  {"Hoch/Runter: Auswahl │ Enter: Scan │ Esc: Zurueck","Up/Down: Select │ Enter: Scan │ Esc: Back"},
  {"Aktualisierung laeuft ...","Update in progress ..."},
  {"OUI-Datenbank aktualisieren","Update OUI database"},
  {"OUI-Datenbank wird heruntergeladen ...","Downloading OUI database ..."},
  {"Datenbank wird geprueft ...","Validating database ..."},
  {"Datenbank wird uebernommen ...","Installing database ..."},
  {"Update abgeschlossen","Update completed"},
  {"Update fehlgeschlagen","Update failed"},
  {"OUI-Update laeuft bereits.","OUI update already running."},
  {"OUI-Update: Datenbankpfad fehlt.","OUI update: database path missing."},
  {"OUI-Update: Download laeuft ...","OUI update: downloading ..."},
  {"OUI-Update fehlgeschlagen:","OUI update failed:"},
  {"OUI aktualisiert:","OUI updated:"},
  {"Eintraege","entries"},
  {"Verbindung zu IEEE wird hergestellt ...","Connecting to IEEE ..."},
  {"OUI-Download zu gross.","OUI download too large."},
  {"OUI-Liste unvollstaendig.","Incomplete OUI list."},
  {"Ungueltiges IEEE-CSV-Format.","Invalid IEEE CSV format."},
  {"Ungueltige IPv4-Adresse.","Invalid IPv4 address."},
  {"CIDR oder IP-Bereich erwartet, z.B. 10.0.0.0/24 oder 10.0.0.1-10.0.0.145 (maximal /16).","Expected CIDR or IP range, e.g. 10.0.0.0/24 or 10.0.0.1-10.0.0.145 (maximum /16)."},
  {"IP-Bereich erwartet, z.B. 10.0.0.1-10.0.0.145.","Expected IP range, e.g. 10.0.0.1-10.0.0.145."},
  {"Ungueltige Endadresse, z.B. 10.0.0.1-25.","Invalid end address, e.g. 10.0.0.1-25."},
  {"Die Endadresse muss groesser oder gleich der Startadresse sein.","The end address must be greater than or equal to the start address."},
  {"Ein IP-Bereich darf hoechstens 65536 Adressen enthalten.","An IP range may contain at most 65536 addresses."},
  {"Ports muessen zwischen 1 und 65535 liegen.","Ports must be between 1 and 65535."},
  {"Kein aktiver IPv4-Multicastadapter gefunden.","No active IPv4 multicast adapter found."},
  {"mDNS-Multicast konnte auf keinem Adapter aktiviert werden.","Could not enable mDNS multicast on any adapter."},
  {"Unvollstaendige LLMNR-Antwort.","Incomplete LLMNR response."},
  {"Unbekannte Option:","Unknown option:"},
  {"Aufruf: Kubscan scan [Subnetz/IP-Bereich] [-csv] [-txt] [-OutputPath <directory>]","Usage: Kubscan scan [subnet/IP-range] [-csv] [-txt] [-OutputPath <directory>]"},
  {"Datum:","Date:"},
  {"IP;DNS;MAC;Hersteller;Ping_ms;Offene_TCP_Ports","IP;DNS;MAC;Vendor;Ping_ms;Open_TCP_Ports"},
  {"FTP-Daten","FTP data"},
  {"Drucker JetDirect","JetDirect printer"},
  {"HTTP alternativ","HTTP alternate"},
  {"A           ARP-Listenmodus / IP-Scan umschalten","A           Switch between ARP listen mode and IP scan"},
  {"F1          Funktionsuebersicht anzeigen","F1          Show help"},
  {"T           Theme auswaehlen","T           Select theme"},
  {"L           Sprache wechseln (Deutsch / Englisch)","L           Switch language (English / German)"},
  {"S           Alle TCP-Ports des markierten Hosts pruefen","S           Scan all TCP ports of the selected host"},
  {"P           TCP-Ports fuer markierten Host eingeben","P           Enter TCP ports for the selected host"},
  {"F2 / Enter  Scan starten","F2 / Enter  Start scan"},
  {"Scanbereich CIDR oder Start-IP bis End-IP mit -","Scan range: CIDR or start IP to end IP with -"},
  {"Leertaste   Hostdetails des ausgewaehlten Hosts","Space       Show details of the selected host"},
  {"Esc         Hostdetails schliessen","Esc         Close host details"},
  {"F3          Letzten Scan wiederholen","F3          Repeat the last scan"},
  {"M           mDNS-Dienste / IP-Scan umschalten","M           Switch between mDNS services and IP scan"},
  {"C           Aktuellen Spaltenwert kopieren","C           Copy the current column value"},
  {"F4          Dauerping starten / stoppen / fortsetzen","F4          Start / stop / resume continuous ping"},
  {"F5          Ergebnisse als CSV exportieren","F5          Export results as CSV"},
  {"F6          Ergebnisse als Plaintext exportieren","F6          Export results as plain text"},
  {"F7          Suche in IP, DNS, MAC und Hersteller","F7          Search IP, DNS, MAC, and vendor"},
  {"Enter: Uebernehmen, Esc: Suche loeschen","Enter: Apply, Esc: Clear search"},
  {"F8          IEEE-OUI-Datenbank aktualisieren","F8          Update IEEE OUI database"},
  {"F9 / Esc    Laufenden Scan abbrechen","F9 / Esc    Cancel the current scan"},
  {"F10         Anwendung beenden","F10         Quit application"},
  {"Hoch/Runter Host in der Liste auswaehlen","Up/Down     Select a host in the list"},
  {"Links/Rechts Sortierspalte waehlen (Ueberschrift blau)","Left/Right  Select sort column (highlighted heading)"},
 };
 // Uebersetzt feste Oberflaechentexte; unbekannte Texte bleiben unveraendert.
 static string T(string text) {
  if(!English || string.IsNullOrEmpty(text)) return text;
  string key=text.Trim(),translated;
  if(!englishText.TryGetValue(key,out translated)) return text;
  int first=text.IndexOf(key,StringComparison.Ordinal);
  return text.Substring(0,first)+translated+text.Substring(first+key.Length);
 }
 // Uebersetzt auch dynamische Statusmeldungen mit angehaengten Werten.
 static string TranslateMessage(string text) {
  if(string.IsNullOrEmpty(text) || !English) return text;
  string exact=T(text); if(exact!=text) return exact;
  if(text.IndexOf('\n')>=0) return string.Join("\n",text.Split('\n').Select(TranslateMessage));
  foreach(string prefix in new[]{"OUI-Update fehlgeschlagen: ","mDNS-Fehler: ","Fehler: ","OUI aktualisiert: ","Ungueltiger Portbereich: ","Unbekannte Option: ","Dateiendung muss ","Scan laeuft "}) {
   if(!text.StartsWith(prefix,StringComparison.Ordinal)) continue;
   string tail=text.Substring(prefix.Length);
   if(tail.EndsWith(" Eintraege",StringComparison.Ordinal)) tail=tail.Substring(0,tail.Length-" Eintraege".Length)+" entries";
   if(tail.EndsWith(" sein.",StringComparison.Ordinal)) tail=tail.Substring(0,tail.Length-6)+".";
   return T(prefix)+TranslateMessage(tail);
  }
  return text;
 }
 // Bereitet interne Statuswerte fuer die ausgewaehlte Anzeigesprache auf.
 static string DisplayStatus(string value) {
  if(value==null) return "";
  switch(value) {
   case "Wird ermittelt ...": case "Werden geprueft ...": case "Abgebrochen": case "Keine im Pruefumfang offen":
   case "Nicht verfuegbar": case "Nicht verfuegbar (Loopback)": case "Nicht verfuegbar (ARP/lokales Netz)":
   case "Nicht verfuegbar (keine IPv4-Adresse)": case "Nicht verfuegbar (MAC-Abfrage fehlgeschlagen)":
   case "Lokal/privat oder Multicast": case "OUI-Datei fehlt": case "Unbekannt": return T(value);
   default: return value;
  }
 }
 // Liefert den angezeigten Hostnamen mit lokalisierten Statuswerten.
 static string DisplayHostName(Host host) {
  return host.NameSource=="Keine Antwort" || host.NameSource=="Abgebrochen" || host.DNS=="Wird ermittelt ..."?T(host.DNS):host.DNS;
 }
 // Uebersetzt gespeicherte Pingmeldungen ohne erneute Netzwerkabfrage.
 static string TranslatePingHistory(string text) {
  int separator=text.IndexOf("  ",StringComparison.Ordinal);
  if(separator<0) return TranslateMessage(text);
  string value=text.Substring(separator+2);
  if(value.StartsWith("Antwort: ",StringComparison.Ordinal)) value=T("Antwort: ")+value.Substring(9);
  else value=TranslateMessage(value);
  return text.Substring(0,separator+2)+value;
 }

 // Erlaubt den Sprachwechsel nur ausserhalb aktiver Texteingaben.
 static bool CanToggleLanguage(ConsoleKeyInfo key) {
  return key.Key==ConsoleKey.L && !searchEditing && !exportPopup && (portScan==null || !portScan.Editing);
 }
 // Wechselt die Sitzungssprache und verwirft zwischengespeicherte Darstellungen.
 static void ToggleLanguage() {
  InvalidateMdnsFrame();
  English=!English;
  renderedModal=null; renderedIdleFrame=null; renderedExportKey=null; renderedExportLines=null;
  renderedOuiProgress=null; renderedOuiLines=null; renderedPingLines=null;
  if(portScan!=null) portScan.Rendered=null;
 }

 sealed class ColorTheme {
  public readonly string Name;
  public readonly int Base,Panel,Text,Muted,Accent,Red,SelectionAccent;
  // Speichert eine unveraenderliche Farbpalette fuer alle Oberflaechenrollen.
  public ColorTheme(string name,int background,int panel,int text,int muted,int accent,int red,int selectionAccent) {
   Name=name; Base=background; Panel=panel; Text=text; Muted=muted; Accent=accent; Red=red; SelectionAccent=selectionAccent;
  }
 }
 // UI adaptations of the original dark palettes; source links are in README.md.
 static readonly ColorTheme[] themes={
  new ColorTheme("Default v1",0x000000,0x000080,0xc0c0c0,0x808080,0x000080,0x800000,0x000080),
  new ColorTheme("Catppuccin Mocha",0x1e1e2e,0x313244,0xcdd6f4,0x9399b2,0x89b4fa,0xf38ba8,0xf9e2af),
  new ColorTheme("Dracula",0x282a36,0x44475a,0xf8f8f2,0x6272a4,0xbd93f9,0xff5555,0x50fa7b),
  new ColorTheme("Rose Pine",0x191724,0x26233a,0xe0def4,0x908caa,0x9ccfd8,0xeb6f92,0xf6c177),
  new ColorTheme("Everforest",0x2d353b,0x3d484d,0xd3c6aa,0x9da9a0,0xa7c080,0xe67e80,0xdbbc7f),
  new ColorTheme("Tokyo Night",0x1a1b26,0x292e42,0xc0caf5,0x737aa2,0x7aa2f7,0xf7768e,0xff9e64),
  new ColorTheme("Gruvbox",0x282828,0x3c3836,0xebdbb2,0xa89984,0xfabd2f,0xfb4934,0x8ec07c),
  new ColorTheme("Default (One Dark Pro)",0x000000,0x282c34,0xabb2bf,0x5c6370,0x61afef,0xe06c75,0xe5c07b)
 };
 const int DefaultThemeIndex=7;
 static int themeIndex=DefaultThemeIndex;
 static string settingsPath=System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),"KubScan","settings.yaml");
 static bool settingsInitialized;
 static string ReadSetting(string key) {
  try {
   foreach(string line in System.IO.File.ReadAllLines(settingsPath)) {
    string value=line.Trim();
    if(!value.StartsWith(key+":",StringComparison.Ordinal)) continue;
    value=value.Substring(key.Length+1).Trim();
    if(value.StartsWith("'")) {
     var result=new System.Text.StringBuilder();
     for(int i=1;i<value.Length;i++) {
      if(value[i]!='\'') { result.Append(value[i]); continue; }
      if(i+1<value.Length && value[i+1]=='\'') { result.Append('\''); i++; continue; }
      string rest=value.Substring(i+1).Trim();
      return rest.Length==0 || rest.StartsWith("#")?result.ToString():null;
     }
     return null;
    }
    if(value.StartsWith("\"")) {
     // Alte Theme-Dateien verwenden doppelte Anfuehrungszeichen.
     int end=value.IndexOf('"',1);
     if(end<0) return null;
     string rest=value.Substring(end+1).Trim();
     return rest.Length==0 || rest.StartsWith("#")?value.Substring(1,end-1):null;
    }
    int comment=value.IndexOf(" #",StringComparison.Ordinal);
    return (comment>=0?value.Substring(0,comment):value).Trim();
   }
  } catch(System.IO.IOException) {} catch(UnauthorizedAccessException) {}
  return null;
 }
 public static void InitializeSettings() {
  if(settingsInitialized) return;
  settingsInitialized=true;
  string output=ReadSetting("export_path");
  if(!string.IsNullOrWhiteSpace(output)) ConfigureExportDirectory(output);
  // Auch vorhandene Theme-Dateien um dokumentierte Einstellungen ergaenzen.
  try { SaveThemeSetting(LoadThemeSetting()); }
  catch(System.IO.IOException) {} catch(UnauthorizedAccessException) {}
 }
 // Die Einstellungsdatei enthaelt einen YAML-Skalar mit einem bekannten Theme-Namen.
 static int LoadThemeSetting() {
  string value=ReadSetting("theme");
  if(string.Equals(value,"Standard",StringComparison.OrdinalIgnoreCase)) return 0;
  if(string.Equals(value,"Default",StringComparison.OrdinalIgnoreCase) || string.Equals(value,"One Dark Pro",StringComparison.OrdinalIgnoreCase)) return DefaultThemeIndex;
  int index=Array.FindIndex(themes,theme=>string.Equals(theme.Name,value,StringComparison.OrdinalIgnoreCase));
  return index<0?DefaultThemeIndex:index;
 }
 static void SaveThemeSetting(int index) {
  string folder=System.IO.Path.GetDirectoryName(settingsPath);
  System.IO.Directory.CreateDirectory(folder);
  string temporary=settingsPath+"."+Guid.NewGuid().ToString("N")+".tmp";
  try {
   string output=ReadSetting("export_path")??"";
   string content="# KubScan settings / Einstellungen\n"+
    "# Theme: Farbschema der Oberflaeche. Auswahl mit T und Enter wird gespeichert.\n"+
    "# Moegliche Werte: "+string.Join(", ",themes.Select(theme=>theme.Name))+"\n"+
    "theme: '"+themes[index].Name+"'\n\n"+
    "# Exportpfad fuer CSV- und TXT-Dateien. Moegliche Werte: '' oder ein Ordnerpfad.\n"+
    "# '' verwendet die bisherige plattformabhaengige Vorbelegung:\n"+
    "# Windows: %USERPROFILE%\\KubScan\\exports\n"+
    "# Linux (portabel): ~/KubScan/exports\n"+
    "# Linux (Paketstarter): $KUBSCAN_DATA_HOME/exports, normalerweise\n"+
    "# ${XDG_DATA_HOME:-$HOME/.local/share}/kubscan/exports\n"+
    "# Eigener Pfad: vorzugsweise absolut; relative Pfade beziehen sich auf das Arbeitsverzeichnis.\n"+
    "# Pfade in einfache Anfuehrungszeichen setzen; enthaltene ' als '' schreiben.\n"+
    "# -OutputPath hat fuer den aktuellen Aufruf Vorrang und wird nicht gespeichert.\n"+
    "export_path: '"+output.Replace("'","''")+"'\n";
   System.IO.File.WriteAllText(temporary,content,new System.Text.UTF8Encoding(false));
   if(System.IO.File.Exists(settingsPath)) System.IO.File.Replace(temporary,settingsPath,null);
   else System.IO.File.Move(temporary,settingsPath);
  } finally { if(System.IO.File.Exists(temporary)) System.IO.File.Delete(temporary); }
 }
 static bool trueColorEnabled,outputModeKnown;
 static IntPtr themeOutputHandle;
 static uint originalOutputMode;
 static ConsoleColor themeForeground=ConsoleColor.Gray,themeBackground=ConsoleColor.Black;
 static ConsoleColor originalForeground,originalBackground;
 // Mischt zwei RGB-Farben mit einem prozentualen Anteil der ersten Farbe.
 static int BlendColor(int first,int second,int firstPercent) {
  int result=0;
  for(int shift=0;shift<=16;shift+=8) result|=((((first>>shift)&255)*firstPercent+((second>>shift)&255)*(100-firstPercent))/100)<<shift;
  return result;
 }
 // Ordnet Konsolenfarben den Rollen der aktiven Truecolor-Palette zu.
 static int ThemeRgb(int index,ConsoleColor color,bool background,ConsoleColor currentBackground) {
  var theme=themes[index];
  switch(color) {
   case ConsoleColor.Black: return theme.Base;
   case ConsoleColor.DarkGray: return theme.Muted;
   case ConsoleColor.DarkBlue:
   case ConsoleColor.Blue:
   case ConsoleColor.DarkCyan:
    return background?theme.Panel:(currentBackground==ConsoleColor.Gray || currentBackground==ConsoleColor.White)?BlendColor(theme.Accent,theme.Base,20):theme.Accent;
   case ConsoleColor.Cyan: return background?theme.Panel:BlendColor(theme.Accent,theme.Text,65);
   case ConsoleColor.Yellow: return theme.SelectionAccent;
   case ConsoleColor.Green: return 0x98c379;
   case ConsoleColor.DarkMagenta: return theme.Accent;
   case ConsoleColor.DarkRed:
   case ConsoleColor.Red: return background?BlendColor(theme.Red,theme.Base,30):theme.Red;
   default: return theme.Text;
  }
 }
 // Erzeugt eine ANSI-Truecolor-Sequenz fuer Vorder- oder Hintergrund.
 static readonly ConcurrentDictionary<long,string> rgbSequences=new ConcurrentDictionary<long,string>();
 static readonly Func<long,string> makeRgbSequence=key=>{
  int rgb=(int)(key>>1); bool background=(key&1)!=0;
  return "\u001b["+(background?48:38)+";2;"+((rgb>>16)&255)+";"+((rgb>>8)&255)+";"+(rgb&255)+"m";
 };
 // Die unveraenderlichen Paletten verwenden dieselben ANSI-Sequenzen in jedem Frame.
 static string RgbSequence(int rgb,bool background) {
  return rgbSequences.GetOrAdd(((long)rgb<<1)|(background?1L:0L),makeRgbSequence);
 }
 // Setzt logische Textfarben und uebertraegt sie bei Bedarf als ANSI-Truecolor.
 static ConsoleColor ThemeForeground {
  // Unix reports -1 when the terminal default color is not known to .NET.
  get { return themeIndex==0?((int)Console.ForegroundColor<0?ConsoleColor.Gray:Console.ForegroundColor):themeForeground; }
  set {
   themeForeground=value;
   if(themeIndex==0 || !trueColorEnabled) Console.ForegroundColor=value;
   else Console.Write(RgbSequence(ThemeRgb(themeIndex,value,false,themeBackground),false));
  }
 }
 // Setzt logische Hintergrundfarben und synchronisiert die ANSI-Ausgabe.
 static ConsoleColor ThemeBackground {
  get { return themeIndex==0?((int)Console.BackgroundColor<0?ConsoleColor.Black:Console.BackgroundColor):themeBackground; }
  set {
   themeBackground=value;
   if(themeIndex==0 || !trueColorEnabled) Console.BackgroundColor=value;
   else {
    Console.Write(RgbSequence(ThemeRgb(themeIndex,value,true,value),true));
    Console.Write(RgbSequence(ThemeRgb(themeIndex,themeForeground,false,value),false));
   }
  }
 }
 // Terminal reverse video also works when .NET suppresses palette colors (NO_COLOR).
 static void BeginSelectedRow(ConsoleColor foreground,ConsoleColor background) {
  if(!IsWindows && themeIndex==0) Console.Write("\u001b[7m");
  else { ThemeForeground=background; ThemeBackground=foreground; }
 }
 static void EndSelectedRow(ConsoleColor foreground,ConsoleColor background) {
  if(!IsWindows && themeIndex==0) Console.Write("\u001b[27m");
  ThemeForeground=foreground; ThemeBackground=background;
 }
 // Establish the complete default palette before clearing/painting the first frame.
 // Terminal defaults (-1) can differ from ANSI black/gray in a user palette.
 static void ApplyDefaultThemeColors() {
  ConsoleColor foreground=!IsWindows && (int)originalForeground<0?ConsoleColor.Gray:originalForeground;
  ConsoleColor background=!IsWindows && (int)originalBackground<0?ConsoleColor.Black:originalBackground;
  ThemeForeground=foreground; ThemeBackground=background;
  if(!IsWindows) Console.Write("\u001b[0m"+PaletteSequence(foreground,false)+PaletteSequence(background,true));
 }
 // Aktiviert ANSI-Ausgabe und sichert den urspruenglichen Konsolenmodus.
 static void InitializeThemeOutput() {
  originalForeground=Console.ForegroundColor; originalBackground=Console.BackgroundColor;
  themeForeground=originalForeground; themeBackground=originalBackground; themeIndex=0;
  if(!IsWindows) { trueColorEnabled=!Console.IsOutputRedirected && Environment.GetEnvironmentVariable("TERM")!="dumb"; outputModeKnown=false; ApplyDefaultThemeColors(); return; }
  themeOutputHandle=GetStdHandle(-11);
  outputModeKnown=GetConsoleMode(themeOutputHandle,out originalOutputMode);
  trueColorEnabled=outputModeKnown && SetConsoleMode(themeOutputHandle,originalOutputMode|4u);
 }
 // Loescht die Konsole passend zur verfuegbaren Farbausgabe.
 static void ClearScreen() {
  if(Console.IsOutputRedirected) return;
  if(themeIndex>0 && trueColorEnabled) Console.Write("\u001b[2J\u001b[H");
  else Console.Clear();
 }
 static bool themePicker;
 static int themeSelection;
 static int themeOriginalIndex;
 static bool themePreviewDirty;
 static int themePreviewWidth,themePreviewHeight;
 static string themePreviousTitle,themePreviousMessage;
 static void OpenThemePicker() {
  if(!trueColorEnabled) { dialogTitle="HINWEIS"; dialogMessage="Themes benoetigen eine Konsole mit ANSI-Farbunterstuetzung."; return; }
  themePreviousTitle=dialogTitle; themePreviousMessage=dialogMessage;
  themeOriginalIndex=themeIndex; themeSelection=themeIndex; themePicker=true; themePreviewDirty=true;
  UpdateThemePicker();
 }
 static void UpdateThemePicker() {
  dialogTitle="Themes";
  dialogMessage=string.Join("\n",themes.Select((theme,i)=>theme.Name+(i==themeSelection?(English?" [selected]":" [ausgewaehlt]"):"")));
 }
 static void HandleThemeKey(ConsoleKey key) {
  int previousSelection=themeSelection;
  switch(key) {
   case ConsoleKey.UpArrow: themeSelection=Math.Max(0,themeSelection-1); break;
   case ConsoleKey.DownArrow: themeSelection=Math.Min(themes.Length-1,themeSelection+1); break;
   case ConsoleKey.Home: themeSelection=0; break;
   case ConsoleKey.End: themeSelection=themes.Length-1; break;
   case ConsoleKey.Enter: case ConsoleKey.Escape:
    themePicker=false; dialogTitle=themePreviousTitle; dialogMessage=themePreviousMessage;
    if(key==ConsoleKey.Enter) {
     if(themeIndex!=themeSelection) ApplyTheme(themeSelection);
     try { SaveThemeSetting(themeSelection); }
     catch(Exception error) {
      if(!(error is System.IO.IOException) && !(error is UnauthorizedAccessException)) throw;
      dialogTitle=English?"ERROR":"FEHLER";
      dialogMessage=(English?"Could not save theme settings: ":"Theme-Einstellungen konnten nicht gespeichert werden: ")+error.Message;
     }
    } else if(themeIndex!=themeOriginalIndex) ApplyTheme(themeOriginalIndex);
    InvalidateMdnsFrame(); renderedIdleFrame=null; renderedModal=null; renderedArpOverlay=null;
    renderedExportKey=null; renderedExportLines=null; renderedOuiProgress=null; renderedOuiLines=null; renderedPingLines=null;
    if(portScan!=null) portScan.Rendered=null;
    return;
  }
  if(themeSelection!=previousSelection) { ApplyTheme(themeSelection); themePreviewDirty=true; }
  UpdateThemePicker();
 }
 // Wendet die bestaetigte Auswahl an und zeichnet die Oberflaeche neu.
 static void ApplyTheme(int index) {
  InvalidateMdnsFrame();
  if(!trueColorEnabled) { dialogTitle="HINWEIS"; dialogMessage="Themes benoetigen eine Konsole mit ANSI-Farbunterstuetzung."; return; }
  themeIndex=index;
  if(themeIndex==0) {
   Console.Write("\u001b[0m");
   ApplyDefaultThemeColors();
  } else { ThemeForeground=ConsoleColor.Gray; ThemeBackground=ConsoleColor.Black; }
  renderedModal=null; renderedIdleFrame=null;
  renderedExportKey=null; renderedExportLines=null; renderedOuiProgress=null; renderedOuiLines=null; renderedPingLines=null;
  if(portScan!=null) portScan.Rendered=null;
  // Die vorhandenen Zeilen beim naechsten Draw direkt ueberzeichnen.
  // Ein vorheriges Loeschen wuerde bis zur Neuzeichnung ein leeres Bild zeigen.
 }
 // Stellt Konsolenfarben und Ausgabemodus beim Beenden wieder her.
 static void RestoreThemeOutput() {
  if(trueColorEnabled) Console.Write("\u001b[0m");
  themeIndex=0;
  Console.ForegroundColor=originalForeground; Console.BackgroundColor=originalBackground;
  if(outputModeKnown) SetConsoleMode(themeOutputHandle,originalOutputMode);
  trueColorEnabled=false;
 }
 static int sortColumn;
 static string searchText="";
 static bool searchEditing;
 // Prueft einen einzelnen Wert ohne Hilfsarray auf den aktuellen Suchtext.
 static bool ContainsSearch(string value) {
  return value!=null && value.IndexOf(searchText,StringComparison.OrdinalIgnoreCase)>=0;
 }
 // Vergleicht rohe und lokalisierte Hostfelder mit dem Suchfilter.
 static bool MatchesSearch(Host host) {
  return searchText.Length==0 || ContainsSearch(host.IP) || ContainsSearch(DisplayHostName(host)) ||
   ContainsSearch(DisplayStatus(host.MAC)) || ContainsSearch(DisplayStatus(host.Vendor)) ||
   ContainsSearch(host.DNS) || ContainsSearch(host.MAC) || ContainsSearch(host.Vendor);
 }
 // Beendet die Texteingabe, damit dieselbe Taste sofort die Liste bewegt.
 static void LeaveSearchForNavigation(ConsoleKey key) {
  if(key==ConsoleKey.UpArrow || key==ConsoleKey.DownArrow || key==ConsoleKey.LeftArrow || key==ConsoleKey.RightArrow || key==ConsoleKey.PageUp || key==ConsoleKey.PageDown || key==ConsoleKey.Home || key==ConsoleKey.End) searchEditing=false;
 }
 // Bearbeitet den Suchfilter und setzt die Listenauswahl auf den ersten Treffer.
 static void HandleSearchKey(ConsoleKeyInfo key) {
  if(key.Key==ConsoleKey.Escape) { searchText=""; searchEditing=false; if(listenMode) arpScroll=0; else selected=0; return; }
  if(key.Key==ConsoleKey.Enter || key.Key==ConsoleKey.F7) { searchEditing=false; return; }
  if((key.Modifiers & ConsoleModifiers.Control)!=0 && key.Key==ConsoleKey.A) { searchText=""; if(listenMode) arpScroll=0; else selected=0; return; }
  if(key.Key==ConsoleKey.Backspace) { if(searchText.Length>0) searchText=searchText.Substring(0,searchText.Length-1); }
  else if(!char.IsControl(key.KeyChar) && searchText.Length<100) searchText+=key.KeyChar;
  if(listenMode) arpScroll=0; else selected=0;
 }
 // Filtert einen threadsicheren Snapshot; numerische IP-Reihenfolge stabilisiert gleiche Sortierwerte.
 static Host[] SortedHosts() => SortHosts(true);
 static Host[] SortHosts(bool keepContinuousOrder) {
  // Snapshot membership before LINQ: concurrent Count/CopyTo calls can race as hosts arrive.
  // Host fields may still finish resolving; only collection membership is frozen here.
  var list=hosts.ToArray().Where(pair=>MatchesSearch(pair.Value)).OrderBy(pair=>pair.Key).Select(pair=>pair.Value);
  if(continuousList && keepContinuousOrder) return list.ToArray();
  return sortColumn==0?list.ToArray():list.OrderBy(h=>sortColumn==1?h.DNS:sortColumn==2?h.MAC:h.Vendor,StringComparer.OrdinalIgnoreCase).ToArray();
 }
 static string copyNotice="";
 static DateTime copyNoticeUntil;
 // Zeigt die Kopierbestaetigung nur bis zum Ablauf ihrer Anzeigedauer.
 static string ClipboardNotice() { return DateTime.UtcNow<copyNoticeUntil?" | "+TranslateMessage(copyNotice):""; }
 // Liest den vollstaendigen Wert der markierten Spalte im aktiven Scanmodus.
 static string SelectedCellValue() {
  if(mdnsMode) {
   var list=SortedMdns(); if(list.Length==0) return null;
   var entry=list[Math.Max(0,Math.Min(mdnsSelected,list.Length-1))];
   return new[]{entry.Name,entry.Type,entry.Host,entry.Address,entry.Port==0?"?":entry.Port.ToString()}[mdnsSort]??"";
  }
  var hostsList=SortedHosts(); if(hostsList.Length==0) return null;
  var host=hostsList[Math.Max(0,Math.Min(selected,hostsList.Length-1))];
  return new[]{host.IP,DisplayHostName(host),DisplayStatus(host.MAC),DisplayStatus(host.Vendor)}[sortColumn]??"";
 }
 // Native Zwischenablagefunktionen: Speicherbesitz geht erst nach SetClipboardData an Windows ueber.
 [DllImport("user32.dll",SetLastError=true)] static extern bool OpenClipboard(IntPtr window);
 [DllImport("user32.dll",SetLastError=true)] static extern bool CloseClipboard();
 [DllImport("user32.dll",SetLastError=true)] static extern bool EmptyClipboard();
 [DllImport("user32.dll",SetLastError=true)] static extern IntPtr SetClipboardData(uint format,IntPtr memory);
 [DllImport("kernel32.dll")] static extern IntPtr GetConsoleWindow();
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr GlobalAlloc(uint flags,UIntPtr bytes);
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr GlobalLock(IntPtr memory);
 [DllImport("kernel32.dll")] static extern bool GlobalUnlock(IntPtr memory);
 [DllImport("kernel32.dll")] static extern IntPtr GlobalFree(IntPtr memory);
 // Uebertraegt Unicode-Text an Windows und gibt nicht uebernommenen Speicher frei.
 static void SetClipboardText(string value) {
  if(!IsWindows) { LinuxClipboard(value); return; }
  byte[] bytes=System.Text.Encoding.Unicode.GetBytes(value+"\0");
  IntPtr memory=GlobalAlloc(2,new UIntPtr((uint)bytes.Length));
  if(memory==IntPtr.Zero) throw new InvalidOperationException("Kein Speicher fuer Zwischenablage.");
  bool opened=false;
  try {
   IntPtr pointer=GlobalLock(memory);
   if(pointer==IntPtr.Zero) throw new InvalidOperationException("Zwischenablagespeicher nicht verfuegbar.");
   try { Marshal.Copy(bytes,0,pointer,bytes.Length); } finally { GlobalUnlock(memory); }
   for(int attempt=0;attempt<5;attempt++) { opened=OpenClipboard(GetConsoleWindow()); if(opened) break; Thread.Sleep(20); }
   if(!opened) throw new InvalidOperationException("Zwischenablage ist belegt.");
   if(!EmptyClipboard() || SetClipboardData(13,memory)==IntPtr.Zero) throw new InvalidOperationException("Zwischenablage konnte nicht geschrieben werden.");
   memory=IntPtr.Zero; // Windows owns the allocation after successful transfer.
  } finally { if(opened) CloseClipboard(); if(memory!=IntPtr.Zero) GlobalFree(memory); }
 }
 // Kopiert die aktive Zelle und meldet Erfolg oder Fehler in der Statuszeile.
 static void CopySelectedCell() {
  string value=SelectedCellValue();
  try {
   if(value==null) copyNotice="Kein Eintrag ausgewaehlt.";
   else { SetClipboardText(value); copyNotice="Spaltenwert kopiert."; }
  } catch(Exception error) { copyNotice=error.Message; }
  copyNoticeUntil=DateTime.UtcNow.AddSeconds(3);
 }

 // Wechselt die Sortierspalte und erhaelt nach Moeglichkeit denselben ausgewaehlten Host.
 static void ChangeSortColumn(int direction) {
  var list=SortedHosts();
  Host current=list.Length==0?null:list[Math.Max(0,Math.Min(selected,list.Length-1))];
  sortColumn=Math.Max(0,Math.Min(3,sortColumn+direction));
  selected=current==null?0:Math.Max(0,Array.IndexOf(SortedHosts(),current));
 }
 static int[] ports;
 static string dialogMessage;
 static string dialogTitle="FEHLER";
 static string scannedSubnet="Noch kein Scan gestartet";
 static bool hasScan;
 static Host detailHost;
 static int hostDetailScroll;
 // Begrenzt die Auswahl und laesst bereits geoeffnete Details der markierten Zeile folgen.
 static void SyncHostDetails(Host[] list) {
  selected=Math.Max(0,Math.Min(selected,list.Length-1));
  if(detailHost!=null) detailHost=list.Length==0?null:list[selected];
 }
 // Oeffnet Details zur aktuellen Auswahl oder schliesst einen offenen Detailbereich.
 static void ConfirmSelectedHost() {
  if(detailHost!=null) { detailHost=null; return; }
  var list=SortedHosts();
  if(list.Length>0) { detailHost=list[Math.Max(0,Math.Min(selected,list.Length-1))]; hostDetailScroll=0; StartHostServices(detailHost); }
 }
 public static string ExportDirectory=System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),"KubScan","exports");
 // Normalisiert Exportordner ohne beim Start Dateien anzulegen.
 public static void ConfigureExportDirectory(string path) {
  if(string.IsNullOrWhiteSpace(path)) throw new ArgumentException("OutputPath must name a directory.");
  ExportDirectory=System.IO.Path.GetFullPath(Environment.ExpandEnvironmentVariables(path));
 }
 // Gemeinsame Startoption fuer EXE, interaktiven Modus und automatischen Scan.
 public static string[] ConfigureStartupArguments(string[] args) {
  InitializeSettings();
  var remaining=new System.Collections.Generic.List<string>(); string path=null;
  for(int i=0;i<args.Length;i++) {
   if(string.Equals(args[i],"-OutputPath",StringComparison.OrdinalIgnoreCase)) {
    if(path!=null || i+1>=args.Length || args[i+1].StartsWith("-")) throw new ArgumentException("Usage: -OutputPath <directory>");
    path=args[++i];
   } else remaining.Add(args[i]);
  }
  if(path!=null) ConfigureExportDirectory(path);
  return remaining.ToArray();
 }
 static volatile string exportMessage="";
 // Reserviert fuer Details maximal ein Drittel der Breite und hoechstens 36 Zeichen.
 static int LeftWidth(int width) { return width-Math.Min(36,width/3)-1; }
 // Maskiert Anfuehrungszeichen und umfasst CSV-Felder mit Anfuehrungszeichen.
 static string CsvValue(string value) { return "\""+(value??"").Replace("\"","\"\"")+"\""; }
 // Erzeugt einen lokalisierten CSV-Export mit Semikolon als Trennzeichen.
 static string Csv(Host[] snapshot) {
  var text=new System.Text.StringBuilder();
  text.Append(T("IP;DNS;MAC;Hersteller;Ping_ms;Offene_TCP_Ports\r\n"));
  foreach(var host in snapshot) text.Append(string.Join(";",new[]{host.IP,DisplayHostName(host),DisplayStatus(host.MAC),DisplayStatus(host.Vendor),host.Ping.ToString(System.Globalization.CultureInfo.InvariantCulture),DisplayStatus(host.Ports)}.Select(CsvValue))).Append("\r\n");
  return text.ToString();
 }
 // Ersetzt Steuerzeichen fuer sichere Tabellenwerte; saubere Strings werden wiederverwendet.
 static string ExportTextValue(string value) {
  if(string.IsNullOrEmpty(value)) return "";
  for(int i=0;i<value.Length;i++) {
   if(!char.IsControl(value[i])) continue;
   // Ordinary display values keep their original string without allocating a character array.
   char[] clean=value.ToCharArray();
   for(int j=i;j<clean.Length;j++) if(char.IsControl(clean[j])) clean[j]=' ';
   return new string(clean);
  }
  return value;
 }
 // Erzeugt die vollstaendige Texttabelle mit Tabulatoren, Scanbereich und Exportdatum.
 static string PlainText(Host[] snapshot,int width) {
  var rows=new System.Collections.Generic.List<string[]>();
  rows.Add(new[]{"IP","DNS","MAC",T("HERSTELLER")});
  foreach(var host in snapshot) rows.Add(new[]{host.IP,DisplayHostName(host),DisplayStatus(host.MAC),DisplayStatus(host.Vendor)}.Select(ExportTextValue).ToArray());
  int[] widths=Enumerable.Range(0,4).Select(i=>rows.Max(row=>row[i].Length)).ToArray();
  var text=new System.Text.StringBuilder();
  text.Append("  Kubware-Kubscan\r\n");
  string date=BerlinNow().ToString("dd.MM.yyyy",System.Globalization.CultureInfo.InvariantCulture);
  text.Append(T("\r\n  Subnetz: ")).Append(T(scannedSubnet)).Append(T(" | Datum: ")).Append(date).Append("\r\n\r\n");
  for(int rowIndex=0;rowIndex<rows.Count;rowIndex++) {
   var row=rows[rowIndex];
   text.Append("  ");
   for(int i=0;i<4;i++) { if(i>0) text.Append("\t"); text.Append(row[i].PadRight(widths[i])); }
   text.Append("\r\n");
   if(rowIndex==0) {
    text.Append("  ");
    for(int i=0;i<4;i++) { if(i>0) text.Append("\t"); text.Append(new string('-',widths[i])); }
    text.Append("\r\n");
   }
  }
  return text.ToString();
 }
 // Erzeugt den datumsbezogenen Dateinamenvorschlag fuer den Exportdialog.
 static string SuggestedExportName(bool csv) {
  return "IPScan_"+BerlinNow().ToString("yyyy-MM-dd")+(csv?".csv":".txt");
 }
 // Exportiert alle Ergebnisse mit einem automatisch vorgeschlagenen Dateinamen.
 public static string ExportResults(bool csv,int width) {
  return ExportNamedResults(csv,width,SuggestedExportName(csv));
 }
 // Prueft Dateinamen, Windows-Sondernamen und die zum Export passende Endung.
 static string ExportFileName(string name,bool csv) {
  if(string.IsNullOrWhiteSpace(name)) throw new ArgumentException("Bitte einen Dateinamen eingeben.");
  if(name.Length>200 || name.IndexOfAny(System.IO.Path.GetInvalidFileNameChars())>=0 || name.IndexOfAny("<>:\"/\\|?*".ToCharArray())>=0 || name.Any(c=>c<32) || name.EndsWith(".") || name.EndsWith(" ")) throw new ArgumentException("Ungueltiger Dateiname (keine Pfade erlaubt).");
  string stem=name.Split('.')[0].ToUpperInvariant();
  if(new[]{"CON","PRN","AUX","NUL","CLOCK$"}.Contains(stem) || System.Text.RegularExpressions.Regex.IsMatch(stem,"^(COM|LPT)[1-9]$")) throw new ArgumentException("Reservierter Windows-Dateiname.");
  string extension=csv?".csv":".txt";
  if(!System.IO.Path.HasExtension(name)) name+=extension;
  if(!name.EndsWith(extension,StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("Dateiendung muss "+extension+" sein.");
  return name;
 }
 // Kopiert Hostfelder aus einem Sammlungssnapshot und legt die Exportdatei ohne Ueberschreiben an.
 public static string ExportNamedResults(bool csv,int width,string name) {
  name=ExportFileName(name,csv);
  System.IO.Directory.CreateDirectory(ExportDirectory);
  string path=System.IO.Path.Combine(ExportDirectory,name);
  WriteExport(path,csv,width,System.IO.FileMode.CreateNew);
  return path;
 }
 static void WriteExport(string path,bool csv,int width,System.IO.FileMode fileMode) {
  var snapshot=hosts.ToArray().OrderBy(x=>x.Key).Select(x=>new Host { IP=x.Value.IP,DNS=x.Value.DNS,MAC=x.Value.MAC,Vendor=x.Value.Vendor,Ping=x.Value.Ping,Ports=x.Value.Ports,NameSource=x.Value.NameSource }).ToArray();
  using(var file=new System.IO.FileStream(path,fileMode,System.IO.FileAccess.Write))
  using(var writer=new System.IO.StreamWriter(file,new System.Text.UTF8Encoding(true))) writer.Write(csv?Csv(snapshot):PlainText(snapshot,width));
 }
 static bool exportPopup,exportCsv,exportSelected,exportSaved;
 static string exportName="",exportError="";
 static int exportCursor;
 static string[] renderedExportLines;
 static string renderedExportKey;
 static int renderedExportX,renderedExportY;
 // Initialisiert und oeffnet den Dialog fuer CSV- oder Textausgabe.
 static void Export(bool csv) {
  exportCsv=csv; exportName=System.IO.Path.GetFileNameWithoutExtension(SuggestedExportName(csv)); exportCursor=exportName.Length;
  exportSelected=false; exportSaved=false; exportError=""; exportPopup=true;
  renderedExportKey=null; renderedExportLines=null; exportMessage="";
 }
 // Bearbeitet Dateiname, Cursor, Auswahl und Speichern im Exportdialog.
 static void HandleExportKey(ConsoleKeyInfo key) {
  if(key.Key==ConsoleKey.Escape || (exportSaved && key.Key==ConsoleKey.Enter)) { exportPopup=false; return; }
  if(exportSaved) return;
  if(key.Key==ConsoleKey.Enter) {
   try {
    if(string.IsNullOrWhiteSpace(exportName)) throw new ArgumentException("Bitte einen Dateinamen eingeben.");
    string name=ExportFileName(exportName+(exportCsv?".csv":".txt"),exportCsv);
    ExportNamedResults(exportCsv,80,name);
    exportSaved=true; exportSelected=false; exportError="";
   } catch(ArgumentException e) { exportError=e.Message; }
     catch(System.IO.IOException e) { exportError=System.IO.File.Exists(System.IO.Path.Combine(ExportDirectory,exportName+(exportCsv?".csv":".txt")))?"Datei existiert bereits. Bitte anderen Namen waehlen.":e.Message; }
     catch(UnauthorizedAccessException e) { exportError=e.Message; }
   return;
  }
  if((key.Modifiers & ConsoleModifiers.Control)!=0 && key.Key==ConsoleKey.A) { exportSelected=true; return; }
  switch(key.Key) {
   case ConsoleKey.LeftArrow: exportCursor=exportSelected?0:Math.Max(0,exportCursor-1); exportSelected=false; break;
   case ConsoleKey.RightArrow: exportCursor=exportSelected?exportName.Length:Math.Min(exportName.Length,exportCursor+1); exportSelected=false; break;
   case ConsoleKey.Home: exportCursor=0; exportSelected=false; break;
   case ConsoleKey.End: exportCursor=exportName.Length; exportSelected=false; break;
   case ConsoleKey.Backspace:
    if(exportSelected) { exportName=""; exportCursor=0; }
    else if(exportCursor>0) { exportName=exportName.Remove(exportCursor-1,1); exportCursor--; }
    exportSelected=false; break;
   case ConsoleKey.Delete:
    if(exportSelected) { exportName=""; exportCursor=0; }
    else if(exportCursor<exportName.Length) exportName=exportName.Remove(exportCursor,1);
    exportSelected=false; break;
   default:
    if(!char.IsControl(key.KeyChar) && exportName.Length<200) {
     if(exportSelected) { exportName=""; exportCursor=0; }
     exportName=exportName.Insert(exportCursor,key.KeyChar.ToString()); exportCursor++; exportSelected=false;
    }
    break;
  }
  exportError="";
 }
 // Zeichnet den Exportdialog und vermeidet unveraenderte Ausgaben.
 static void DrawExportDialog(int width,int height) {
  if(!exportPopup) return;
  int boxWidth=Math.Min(84,width-4),x=(width-boxWidth)/2,y=(height-11)/2,inner=boxWidth-2;
  string key=exportName+"\u2502"+exportCursor+"\u2502"+exportSelected+"\u2502"+exportSaved+"\u2502"+exportError+"\u2502"+width+"\u2502"+height;
  if(key==renderedExportKey) return;
  string extension=exportCsv?".csv":".txt";
  int fieldWidth=inner-8;
  string visible=exportName;
  int from=exportSaved?0:Math.Max(0,exportCursor-(fieldWidth-2));
  visible=visible.Substring(Math.Min(from,visible.Length));
  visible=visible.Length>fieldWidth?visible.Substring(0,fieldWidth):visible.PadRight(fieldWidth);
  string border="\u250c"+new string('\u2500',inner)+"\u2510";
  string bottom="\u2514"+new string('\u2500',inner)+"\u2518";
  string[] contents={
   border,
   "\u2502"+Cell(" Export "+(exportCsv?"CSV":"TXT")+(exportSaved?T(" - gespeichert"):""),inner)+"\u2502",
   "\u2502"+Cell(T(" Ordner: ")+ExportDirectory,inner)+"\u2502",
   "\u2502"+Cell(T(" Dateiname (Endung fest):"),inner)+"\u2502",
   "\u2502 "+visible+" "+extension+"  \u2502",
   "\u2502"+new string(' ',inner)+"\u2502",
   "\u2502"+Cell(exportSaved?T(" Datei erfolgreich gespeichert."):" "+TranslateMessage(exportError),inner)+"\u2502",
   "\u2502"+new string(' ',inner)+"\u2502",
   "\u2502"+Cell(exportSaved?T(" Enter / Esc: Schliessen"):T(" Enter: Speichern \u2502 Esc: Abbrechen"),inner)+"\u2502",
   "\u2502"+Cell(exportSaved?"":T(" Ctrl+A: Alles markieren \u2502 Pfeiltasten: Cursor"),inner)+"\u2502",
   bottom
  };
  bool full=renderedExportKey==null || renderedExportLines==null || renderedExportX!=x || renderedExportY!=y || renderedExportLines[0].Length!=boxWidth;
  ConsoleColor foreground=ThemeForeground,background=ThemeBackground;
  try {
   for(int row=0;row<contents.Length;row++) {
    // The input color can change without its text changing.
    if(!full && row!=4 && contents[row]==renderedExportLines[row]) continue;
    Console.SetCursorPosition(x,y+row);
    if(row==4) {
     ThemeForeground=ConsoleColor.White; ThemeBackground=ConsoleColor.DarkBlue; Console.Write("\u2502");
     ThemeForeground=exportSelected?ConsoleColor.Black:ConsoleColor.White; ThemeBackground=exportSelected?ConsoleColor.White:MenuBackground;
     Console.Write(" "+visible);
     ThemeForeground=ConsoleColor.White; ThemeBackground=ConsoleColor.DarkBlue;
     Console.Write(" "+extension+"  \u2502");
     continue;
    }
    ThemeForeground=row==4 && exportSelected?ConsoleColor.Black:ConsoleColor.White;
    ThemeBackground=row==4?(exportSelected?ConsoleColor.White:MenuBackground):ConsoleColor.DarkBlue;
    if(row==1) WritePopupHeading(contents[row]); else Console.Write(contents[row]);
   }
   if(!exportSaved) {
    int cursorColumn=2+exportCursor-from;
    if(cursorColumn>=2 && cursorColumn<2+fieldWidth) {
     Console.SetCursorPosition(x+cursorColumn,y+4);
     ThemeForeground=exportSelected?ConsoleColor.White:MenuBackground;
     ThemeBackground=ConsoleColor.Black;
     Console.Write(exportCursor<exportName.Length?exportName[exportCursor]:' ');
    }
   }
  } finally { ThemeForeground=foreground; ThemeBackground=background; }
  renderedExportLines=contents; renderedExportKey=key; renderedExportX=x; renderedExportY=y;
 }
 static readonly string[] headerLines={"KubScan "+Version};
 // Shared first row: fixed app/version on the left, exact mode label on the right.
 static string ModeHeader(int width) {
  string left=headerLines[0],mode=listenMode?"Arp Watch":mdnsMode?"mDNS List":"IP Scan";
  if(width<left.Length+mode.Length+1) return Cell(left,Math.Max(0,width));
  return left.PadRight(width-mode.Length)+mode;
 }
 static string message="Subnetz eingeben, Enter startet.";
 // Validiert vier IPv4-Oktette und wandelt sie in eine numerisch sortierbare Adresse um.
 static uint ParseIPv4(string value) {
  string[] octets=value.Split('.'); uint address=0;
  if(octets.Length!=4) throw new ArgumentException("Ungueltige IPv4-Adresse.");
  foreach(string octet in octets) {
   byte number;
   if(octet.Length==0 || octet.Any(c=>c<'0'||c>'9') || !byte.TryParse(octet,out number)) throw new ArgumentException("Ungueltige IPv4-Adresse.");
   address=(address<<8)|number;
  }
  return address;
 }
 // Expandiert CIDR-Netze und volle oder verkuerzte IPv4-Bereiche innerhalb des Groessenlimits.
 public static uint[] Parse(string input) {
  input=(input??"").Trim();
  if(input.Contains("-")) {
   string[] range=input.Split('-');
   if(range.Length!=2) throw new ArgumentException("IP-Bereich erwartet, z.B. 10.0.0.1-10.0.0.145.");
   string firstAddress=range[0].Trim(),lastAddress=range[1].Trim();
   uint first=ParseIPv4(firstAddress);
   if(!lastAddress.Contains(".")) {
    byte lastOctet;
    if(lastAddress.Length==0 || lastAddress.Any(c=>c<'0'||c>'9') || !byte.TryParse(lastAddress,out lastOctet)) throw new ArgumentException("Ungueltige Endadresse, z.B. 10.0.0.1-25.");
    lastAddress=firstAddress.Substring(0,firstAddress.LastIndexOf('.')+1)+lastOctet;
   }
   uint last=ParseIPv4(lastAddress);
   if(last<first) throw new ArgumentException("Die Endadresse muss groesser oder gleich der Startadresse sein.");
   ulong count=(ulong)last-first+1;
   if(count>65536) throw new ArgumentException("Ein IP-Bereich darf hoechstens 65536 Adressen enthalten.");
   return Enumerable.Range(0,(int)count).Select(i=>first+(uint)i).ToArray();
  }
  string[] p=input.Split('/'); int prefix;
  if(p.Length!=2 || !int.TryParse(p[1],out prefix) || prefix<16 || prefix>32) throw new ArgumentException("CIDR oder IP-Bereich erwartet, z.B. 10.0.0.0/24 oder 10.0.0.1-10.0.0.145 (maximal /16).");
  uint ip=ParseIPv4(p[0]);
  uint start=ip & (uint.MaxValue << (32-prefix)); int size=1<<(32-prefix),skip=prefix<31?1:0;
  return Enumerable.Range(skip,size-2*skip).Select(i=>start+(uint)i).ToArray();
 }
 // Normalisiert den Scanbereich fuer Rescan und Export unabhaengig vom Eingabefeld.
 static string ScanTargetLabel(string input,uint[] addresses) {
  if(input.Contains("-")) return IP(addresses[0])+"-"+IP(addresses[addresses.Length-1]);
  int prefix=int.Parse(input.Trim().Split('/')[1]);
  return IP(addresses[0] & (uint.MaxValue << (32-prefix)))+"/"+prefix;
 }
 // Bevorzugt einen aktiven IPv4-Adapter mit Gateway fuer die /24-Vorbelegung.
 static string DefaultSubnet() {
  try {
   var candidates=new System.Collections.Generic.List<Tuple<bool,IPAddress>>();
   foreach(var adapter in NetworkInterface.GetAllNetworkInterfaces()) {
    if(adapter.OperationalStatus!=OperationalStatus.Up || adapter.NetworkInterfaceType==NetworkInterfaceType.Loopback || adapter.NetworkInterfaceType==NetworkInterfaceType.Tunnel) continue;
    try {
     var properties=adapter.GetIPProperties();
     bool gateway=properties.GatewayAddresses.Any(g=>g.Address.AddressFamily==AddressFamily.InterNetwork && !g.Address.Equals(IPAddress.Any));
     foreach(var address in properties.UnicastAddresses) {
      if(address.Address.AddressFamily!=AddressFamily.InterNetwork || IPAddress.IsLoopback(address.Address)) continue;
      var bytes=address.Address.GetAddressBytes();
      if(bytes[0]==0 || (bytes[0]==169 && bytes[1]==254)) continue;
      candidates.Add(Tuple.Create(gateway,address.Address));
     }
    } catch(NetworkInformationException) {}
   }
   var candidate=candidates.OrderByDescending(c=>c.Item1).FirstOrDefault();
   return candidate==null?"":Subnet24(candidate.Item2);
  } catch(NetworkInformationException) { return ""; }
 }
 // Leitet aus einer IPv4-Adresse die normalisierte /24-Netzadresse ab.
 static string Subnet24(IPAddress address) {
  byte[] bytes=address.GetAddressBytes();
  return string.Format("{0}.{1}.{2}.0/24",bytes[0],bytes[1],bytes[2]);
 }
 // Formatiert eine numerische IPv4-Adresse in punktierter Schreibweise.
 static string IP(uint n) { return string.Format("{0}.{1}.{2}.{3}",n>>24,(n>>16)&255,(n>>8)&255,n&255); }
 // Verwirft leere Namen und Antworten, die nur eine IP-Adresse enthalten.
 static bool UsableHostName(string name) {
  IPAddress address;
  return !string.IsNullOrWhiteSpace(name) && !IPAddress.TryParse(name.TrimEnd('.'),out address) && !name.Any(char.IsControl);
 }
 // Sucht im geschuetzten mDNS-Cache nach einem Hostnamen mit exakt passender IP.
 static string CachedMdnsName(string ip) {
  lock(mdnsLock) return mdnsEntries.Values.Where(entry=>UsableHostName(entry.Host) && entry.Address.Split(',').Any(value=>value.Trim().Equals(ip,StringComparison.OrdinalIgnoreCase))).Select(entry=>entry.Host).OrderBy(name=>name,StringComparer.OrdinalIgnoreCase).FirstOrDefault();
 }
 // Fuehrt DNS, mDNS, NetBIOS und LLMNR in Reihenfolge aus; Abbruch verhindert weitere Fallbacks.
 static async Task ResolveHostName(Host host,CancellationToken token,Func<Task<string>> dns,Func<string> mdns,Func<Task<string>> netbios,Func<Task<string>> llmnr) {
  host.NameSource="Wird ermittelt ...";
  string[] sources={"DNS (Systemresolver)","mDNS","NetBIOS","LLMNR"};
  for(int step=0;step<sources.Length;step++) {
   if(token.IsCancellationRequested) break;
   string name=null;
   try { name=step==0?await dns():step==1?mdns():step==2?await netbios():await llmnr(); }
   catch(OperationCanceledException) { if(token.IsCancellationRequested) break; }
   catch(SocketException) {} catch(System.IO.IOException) {} catch(FormatException) {} catch(ObjectDisposedException) {}
   if(token.IsCancellationRequested) break;
   if(UsableHostName(name)) { host.DNS=name.TrimEnd('.'); host.NameSource=sources[step]; return; }
  }
  host.DNS=token.IsCancellationRequested?"Abgebrochen":"Kein Hostname ermittelt";
  host.NameSource=token.IsCancellationRequested?"Abgebrochen":"Keine Antwort";
 }
 // Begrenzt die Wartezeit der Windows-DNS-Aufloesung und beruecksichtigt Abbruch.
 static async Task<string> SystemHostName(string ip,CancellationToken token) {
  var lookup=Dns.GetHostEntryAsync(ip);
  if(await Task.WhenAny(lookup,Task.Delay(1500,token))==lookup) {
   try { return (await lookup).HostName; } catch(SocketException) { return null; }
  }
  Observe(lookup); return null;
 }
 // Verbindet die konkreten Namensabfragen mit der gemeinsamen Fallback-Reihenfolge.
 static async Task DnsName(Host host,CancellationToken token) {
  await ResolveHostName(host,token,()=>SystemHostName(host.IP,token),()=>CachedMdnsName(host.IP),()=>NetbiosName(host.IP,token),()=>LlmnrName(host.IP,token));
 }
 // Erzeugt eine NBSTAT-Abfrage mit der angegebenen Transaktionskennung.
 static byte[] NetbiosQuery(int id) {
  byte[] packet=new byte[50]; packet[0]=(byte)(id>>8); packet[1]=(byte)id; packet[5]=1; packet[12]=32;
  for(int i=0;i<16;i++) { int value=i==0?42:0; packet[13+i*2]=(byte)('A'+(value>>4)); packet[14+i*2]=(byte)('A'+(value&15)); }
  packet[47]=33; packet[49]=1; return packet;
 }
 // Validiert NBSTAT-Antworten und waehlt einen eindeutigen Computer- oder Servernamen.
 static string ParseNetbiosName(byte[] packet,int id) {
  if(packet.Length<12 || DnsWord(packet,0)!=id || (packet[2]&128)==0 || (packet[3]&15)!=0) return null;
  int offset=12;
  for(int i=0;i<DnsWord(packet,4);i++) { DnsReadName(packet,ref offset); offset+=4; if(offset>packet.Length) throw new FormatException(); }
  string server=null;
  for(int i=0;i<DnsWord(packet,6);i++) {
   DnsReadName(packet,ref offset); int type=DnsWord(packet,offset),recordClass=DnsWord(packet,offset+2),length=DnsWord(packet,offset+8); offset+=10;
   int end=offset+length; if(end>packet.Length) throw new FormatException();
   if(type==33 && recordClass==1 && length>0) {
    int count=packet[offset++]; if(offset+count*18>end) throw new FormatException();
    for(int n=0;n<count;n++,offset+=18) {
     int flags=DnsWord(packet,offset+16),suffix=packet[offset+15];
     if((flags&0x8000)!=0 || (flags&0x0400)==0 || (flags&0x1800)!=0 || (suffix!=0 && suffix!=32)) continue;
     string name=System.Text.Encoding.ASCII.GetString(packet,offset,15).TrimEnd(' ','\0');
     if(!UsableHostName(name) || name=="*") continue;
     if(suffix==0) return name; server=name;
    }
   }
   offset=end;
  }
  return server;
 }
 // Fragt den NetBIOS-Namen per UDP 137 mit Zeitlimit ab.
 static async Task<string> NetbiosName(string ip,CancellationToken token) {
  if(token.IsCancellationRequested) return null;
  try { using(var client=new UdpClient(AddressFamily.InterNetwork)) {
   client.Connect(IPAddress.Parse(ip),137);
   int id=(int)(Guid.NewGuid().GetHashCode()&65535); byte[] packet=NetbiosQuery(id);
   await client.SendAsync(packet,packet.Length);
   var response=client.ReceiveAsync();
   if(await Task.WhenAny(response,Task.Delay(700,token))!=response) { Observe(response); return null; }
   return ParseNetbiosName((await response).Buffer,id);
  }
  } catch(SocketException) { return null; } catch(ObjectDisposedException) { return null; }
 }
 // Erzeugt den Reverse-DNS-Namen fuer eine IPv4-PTR-Abfrage.
 static string ReverseIpv4Name(string ip) { return string.Join(".",IPAddress.Parse(ip).GetAddressBytes().Reverse())+".in-addr.arpa."; }
 // Liest die benoetigte Paketlaenge aus einem TCP-Stream oder erkennt Verbindungsende.
 static async Task ReadNamePacket(System.IO.Stream stream,byte[] bytes,CancellationToken token) {
  int offset=0;
  while(offset<bytes.Length) { int count=await stream.ReadAsync(bytes,offset,bytes.Length-offset,token); if(count==0) throw new System.IO.IOException("Unvollstaendige LLMNR-Antwort."); offset+=count; }
 }
 // Prueft Kennung und Frage der LLMNR-PTR-Antwort vor der Namensuebernahme.
 static string ParseLlmnrName(byte[] packet,int id,string reverse) {
  if(packet.Length<12 || DnsWord(packet,0)!=id || (packet[2]&0x7e)!=0 || (packet[3]&15)!=0 || DnsWord(packet,6)==0) return null;
  return ParseMdns(packet).Where(record=>record.Type==12 && record.Ttl>0 && record.Name.Equals(reverse,StringComparison.OrdinalIgnoreCase)).Select(record=>record.Target).FirstOrDefault(UsableHostName);
 }
 // Sendet eine laengenpraefixierte LLMNR-TCP-Abfrage und wertet die Antwort aus.
 static async Task<string> LlmnrExchange(TcpClient client,string ip,CancellationToken token) {
  await client.ConnectAsync(ip,5355);
  string reverse=ReverseIpv4Name(ip); int id=(int)(Guid.NewGuid().GetHashCode()&65535);
  byte[] packet=MdnsQuery(reverse,12); packet[0]=(byte)(id>>8); packet[1]=(byte)id;
  var stream=client.GetStream(); byte[] length={(byte)(packet.Length>>8),(byte)packet.Length};
  await stream.WriteAsync(length,0,2,token); await stream.WriteAsync(packet,0,packet.Length,token);
  await ReadNamePacket(stream,length,token); int size=DnsWord(length,0); if(size<12 || size>8192) return null;
  byte[] answer=new byte[size]; await ReadNamePacket(stream,answer,token);
  return ParseLlmnrName(answer,id,reverse);
 }
 // Begrenzt Verbindungsaufbau und LLMNR-Abfrage gemeinsam auf das vorgesehene Zeitlimit.
 static async Task<string> LlmnrName(string ip,CancellationToken token) {
  if(token.IsCancellationRequested) return null;
  using(var client=new TcpClient(AddressFamily.InterNetwork)) {
   try {
    var exchange=LlmnrExchange(client,ip,token);
    if(await Task.WhenAny(exchange,Task.Delay(900,token))!=exchange) { Observe(exchange); return null; }
    return await exchange;
   } catch(OperationCanceledException) { return null; } catch(ObjectDisposedException) { return null; } catch(SocketException) { return null; } catch(System.IO.IOException) { return null; }
  }
 }
 [DllImport("iphlpapi.dll", ExactSpelling=true)]
 // Windows-ARP fuer lokale IPv4-Ziele; Statuscodes werden in MacAddress ausgewertet.
 static extern uint SendARP(uint destination, uint source, byte[] address, ref uint length);
 // Formatiert MAC-Bytes als hexadezimale Oktette mit Doppelpunkten.
 static string FormatMac(byte[] bytes) { return string.Join(":",bytes.Select(b=>b.ToString("X2"))); }
 // Ermittelt lokale Adapter- oder IPv4-ARP-Adressen und liefert aussagekraeftige Statuswerte.
 static string MacAddress(string ip) {
  var target=IPAddress.Parse(ip); byte[] destination=target.GetAddressBytes();
  if(IPAddress.IsLoopback(target)) return "Nicht verfuegbar (Loopback)";
  try {
   foreach(var adapter in NetworkInterface.GetAllNetworkInterfaces()) {
    if(adapter.OperationalStatus!=OperationalStatus.Up || adapter.NetworkInterfaceType==NetworkInterfaceType.Loopback) continue;
    foreach(var local in adapter.GetIPProperties().UnicastAddresses) {
     if(local.Address.AddressFamily!=AddressFamily.InterNetwork || local.IPv4Mask==null) continue;
     var physical=adapter.GetPhysicalAddress().GetAddressBytes();
     if(local.Address.Equals(target)) return physical.Length==6?FormatMac(physical):"Nicht verfuegbar";
     byte[] own=local.Address.GetAddressBytes(), mask=local.IPv4Mask.GetAddressBytes();
     bool same=true; for(int i=0;i<4;i++) if((own[i]&mask[i])!=(destination[i]&mask[i])) same=false;
     if(!same) continue;
     if(!IsWindows) { string found=LinuxMac(ip,adapter.Name); if(found!=null) return found; continue; }
     byte[] mac=new byte[6]; uint length=6;
     if(SendARP(BitConverter.ToUInt32(destination,0),BitConverter.ToUInt32(own,0),mac,ref length)==0 && length==6 && mac.Any(b=>b!=0)) return FormatMac(mac);
    }
   }
  } catch(NetworkInformationException) {} catch(SocketException) {}
  return "Nicht verfuegbar (ARP/lokales Netz)";
 }
 // Linux-Nachbartabelle wird durch die bereits erfolgte Pingpruefung befuellt.
 static string LinuxMacAddress(string ip) {
  try {
   foreach(string line in System.IO.File.ReadLines("/proc/net/arp")) {
    string[] fields=line.Split((char[])null,StringSplitOptions.RemoveEmptyEntries);
    if(fields.Length>=6 && fields[0]==ip && fields[2]!="0x0" && fields[3]!="00:00:00:00:00:00") return fields[3].ToUpperInvariant();
   }
  } catch(System.IO.IOException) {} catch(UnauthorizedAccessException) {}
  return "Nicht verfuegbar (ARP/lokales Netz)";
 }
 static volatile System.Collections.Generic.Dictionary<string,string> oui=new System.Collections.Generic.Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
 public static string OuiPath;
 static Task ouiUpdate;
 static bool ouiPopup;
 static volatile int ouiProgress;
 static volatile string ouiPhase="";
 static long ouiReceived,ouiLength;
 static string renderedOuiProgress;
 static string[] renderedOuiLines;
 static ConsoleColor[][] renderedOuiColors;
 static int renderedOuiX,renderedOuiY;
 // Merkt den Datenbankpfad und laedt die lokale Herstellerzuordnung.
 public static void LoadOui(string path) {
  OuiPath=System.IO.Path.GetFullPath(path);
  if(System.IO.File.Exists(OuiPath)) oui=ReadOui(OuiPath);
 }
 public static void LoadBundledOui() {
  string folder=System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"KubScan");
  OuiPath=System.IO.Path.Combine(folder,"oui.csv");
  if(System.IO.File.Exists(OuiPath)) { oui=ReadOui(OuiPath); return; }
  using(var stream=typeof(App).Assembly.GetManifestResourceStream("KubScan.oui.csv")) {
   if(stream==null) throw new System.IO.FileNotFoundException("Embedded OUI database missing.");
   using(var reader=new System.IO.StreamReader(stream)) oui=ParseOuiLines(ReadLines(reader));
  }
 }
 static System.Collections.Generic.IEnumerable<string> ReadLines(System.IO.TextReader reader) {
  string line; while((line=reader.ReadLine())!=null) yield return line;
 }
 // Liest die IEEE-MA-L-Datei in eine nach MAC-Praefixen indizierte Zuordnung.
 static System.Collections.Generic.Dictionary<string,string> ReadOui(string path) {
  return ParseOuiLines(System.IO.File.ReadLines(path));
 }
 static readonly System.Text.RegularExpressions.Regex ouiLinePattern=new System.Text.RegularExpressions.Regex("^[^,]*,([0-9A-Fa-f]{6}),(\"(?:[^\"]|\"\")*\"|[^,]*)",System.Text.RegularExpressions.RegexOptions.Compiled);
 static System.Collections.Generic.Dictionary<string,string> ParseOuiLines(System.Collections.Generic.IEnumerable<string> lines) {
  var entries=new System.Collections.Generic.Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
  foreach(string line in lines) {
   string assignment,name;
   if(TryReadOuiLine(line,out assignment,out name)) { entries[assignment]=name; continue; }
   // Ungewoehnliche oder fehlerhafte CSV-Zeilen behalten die bisherige Regex-Semantik.
   var match=ouiLinePattern.Match(line);
   if(!match.Success) continue;
   name=match.Groups[2].Value;
   if(name.StartsWith("\"")) name=name.Substring(1,name.Length-2).Replace("\"\"","\"");
   entries[match.Groups[1].Value]=name;
  }
  return entries;
 }
 static bool TryReadOuiLine(string line,out string assignment,out string name) {
  assignment=null; name=null;
  if(line==null) return false;
  int comma=line.IndexOf(',');
  if(comma<0 || line.Length-comma<8 || line[comma+7]!=',') return false;
  for(int index=comma+1;index<comma+7;index++) {
   char value=line[index];
   if(!((value>='0' && value<='9') || (value>='A' && value<='F') || (value>='a' && value<='f'))) return false;
  }
  int start=comma+8;
  if(start<line.Length && line[start]=='"') {
   bool escaped=false; int close=start+1;
   for(;close<line.Length;close++) {
    if(line[close]!='"') continue;
    if(close+1<line.Length && line[close+1]=='"') { escaped=true; close++; continue; }
    break;
   }
   if(close==line.Length || (close+1<line.Length && line[close+1]!=',')) return false;
   name=line.Substring(start+1,close-start-1);
   if(escaped) name=name.Replace("\"\"","\"");
  } else {
   int end=line.IndexOf(',',start);
   name=line.Substring(start,(end<0?line.Length:end)-start);
  }
  assignment=line.Substring(comma+1,6);
  return true;
 }
 // Prueft den Download, ersetzt die Datenbank atomar und aktualisiert vorhandene Herstellerwerte.
 static void InstallOui(string downloadedPath) {
  using(var reader=new System.IO.StreamReader(downloadedPath)) {
   string header=reader.ReadLine();
   if(header==null || !header.StartsWith("Registry,Assignment,Organization Name,",StringComparison.Ordinal)) throw new System.IO.InvalidDataException("Ungueltiges IEEE-CSV-Format.");
  }
  ouiPhase="Datenbank wird geprueft ..."; ouiProgress=94;
  var replacement=ReadOui(downloadedPath);
  if(replacement.Count<1000) throw new System.IO.InvalidDataException("OUI-Liste unvollstaendig.");
  ouiPhase="Datenbank wird uebernommen ..."; ouiProgress=98;
  if(System.IO.File.Exists(OuiPath)) System.IO.File.Replace(downloadedPath,OuiPath,null);
  else System.IO.File.Move(downloadedPath,OuiPath);
  oui=replacement;
  foreach(var host in hosts.Values) host.Vendor=Vendor(host.MAC);
  exportMessage="OUI aktualisiert: "+replacement.Count+" Eintraege";
  ouiPhase="Update abgeschlossen"; ouiProgress=100;
 }
 // Laedt die OUI-Datei im Hintergrund und veroeffentlicht Fortschritt und Abschlussstatus.
 static void UpdateOui() { BeginOuiUpdate(CancellationToken.None); }
 static void BeginOuiUpdate(CancellationToken token) {
  if(ouiUpdate!=null && !ouiUpdate.IsCompleted) { exportMessage="OUI-Update laeuft bereits."; return; }
  if(string.IsNullOrWhiteSpace(OuiPath)) { exportMessage="OUI-Update: Datenbankpfad fehlt."; return; }
  ouiPopup=true; renderedOuiProgress=null;
  ouiProgress=0; ouiPhase="Verbindung zu IEEE wird hergestellt ...";
  Interlocked.Exchange(ref ouiReceived,0); Interlocked.Exchange(ref ouiLength,0);
  exportMessage="OUI-Update: Download laeuft ...";
  ouiUpdate=Task.Run(()=>{
   System.IO.Directory.CreateDirectory(System.IO.Path.GetDirectoryName(OuiPath));
   string temporary=OuiPath+"."+Guid.NewGuid().ToString("N")+".tmp";
   try {
    ServicePointManager.SecurityProtocol|=SecurityProtocolType.Tls12;
    var request=(HttpWebRequest)WebRequest.Create("https://standards-oui.ieee.org/oui/oui.csv");
    request.Timeout=30000; request.ReadWriteTimeout=30000; request.UserAgent="Kubscan OUI Updater";
    using(token.Register(()=>request.Abort()))
    using(var response=(HttpWebResponse)request.GetResponse())
    using(var source=response.GetResponseStream())
    using(var target=new System.IO.FileStream(temporary,System.IO.FileMode.CreateNew,System.IO.FileAccess.Write)) {
     Interlocked.Exchange(ref ouiLength,response.ContentLength);
     ouiPhase="OUI-Datenbank wird heruntergeladen ...";
     ouiProgress=response.ContentLength>0?0:-1;
     byte[] buffer=new byte[65536]; int read; long bytes=0;
     while((read=source.Read(buffer,0,buffer.Length))>0) {
      bytes+=read;
      if(bytes>50L*1024*1024) throw new System.IO.InvalidDataException("OUI-Download zu gross.");
      target.Write(buffer,0,read);
      Interlocked.Exchange(ref ouiReceived,bytes);
      ouiProgress=response.ContentLength>0?(int)Math.Min(90,bytes*90/response.ContentLength):-1;
     }
    }
    token.ThrowIfCancellationRequested();
    InstallOui(temporary);
   } catch(Exception e) {
    exportMessage=token.IsCancellationRequested?ServiceText("OUI-Update abgebrochen.","OUI update cancelled."):"OUI-Update fehlgeschlagen: "+e.Message;
    ouiPhase=token.IsCancellationRequested?"":"Update fehlgeschlagen"; ouiProgress=-2;
   }
   finally {
    try { if(System.IO.File.Exists(temporary)) System.IO.File.Delete(temporary); }
    catch(System.IO.IOException) {} catch(UnauthorizedAccessException) {}
   }
  });
 }
 // Ordnet MAC-Praefixe lokal zu und kennzeichnet private, Multicast- oder unbekannte Adressen.
 static string Vendor(string mac) {
  var database=oui;
  string key=mac.Replace(":","").Replace("-","");
  if(key.Length!=12 || key.Any(c=>!Uri.IsHexDigit(c))) return "Nicht verfuegbar";
  byte first=Convert.ToByte(key.Substring(0,2),16);
  if((first&3)!=0) return "Lokal/privat oder Multicast";
  string name;
  return database.TryGetValue(key.Substring(0,6),out name)?name:database.Count==0?"OUI-Datei fehlt":"Unbekannt";
 }
 // Bereinigt Steuerzeichen und fuellt oder kuerzt eine Zelle auf die vorgegebene Breite.
 static string Cell(string text,int width) {
  text=ExportTextValue(text);
  return text.Length<=width?text.PadRight(width):width<4?text.Substring(0,width):text.Substring(0,width-3)+"...";
 }
 // Ermittelt benoetigte Spaltenbreiten in einem Durchlauf und verteilt das Platzbudget.
 static int[] ListColumnWidths(Host[] snapshot,int width) {
  int ipWidth=2,wantedDns=7,wantedVendor=10;
  foreach(var host in snapshot) {
   ipWidth=Math.Max(ipWidth,(host.IP??"").Length);
   wantedDns=Math.Max(wantedDns,(DisplayHostName(host)??"").Length);
   wantedVendor=Math.Max(wantedVendor,(DisplayStatus(host.Vendor)??"").Length);
  }
  int budget=width-ipWidth-17-6;
  int vendorMinimum=Math.Min(10,Math.Max(1,budget-7));
  int dnsWidth=Math.Min(wantedDns,Math.Max(7,budget-vendorMinimum));
  int vendorWidth=Math.Min(wantedVendor,Math.Max(1,budget-dnsWidth));
  return new[]{ipWidth,dnsWidth,17,vendorWidth};
 }
 // Verteilt freien Platz gleichmaessig auf die drei Zwischenraeume der Hosttabelle.
 static string Columns(string ip,string dns,string mac,string vendor,int width,int[] sizes) {
  int gapSpace=Math.Max(0,width-sizes.Sum());
  int gap=gapSpace/3,remainder=gapSpace%3;
  string gap1=new string(' ',gap+(remainder>0?1:0));
  string gap2=new string(' ',gap+(remainder>1?1:0));
  string gap3=new string(' ',gap);
  return Cell(Cell(ip,sizes[0])+gap1+Cell(dns,sizes[1])+gap2+Cell(mac,sizes[2])+gap3+Cell(vendor,sizes[3]),width);
 }
 // Formatiert eine Hostzeile mit berechneten oder vorgegebenen Spaltenbreiten.
 static string HostRow(Host host,int width) {
  return HostRow(host,width,ListColumnWidths(new[]{host},Math.Max(48,width-2)));
 }
 // Formatiert eine Hostzeile mit berechneten oder vorgegebenen Spaltenbreiten.
 static string HostRow(Host host,int width,int[] sizes) {
  return Cell("  "+Columns(host.IP,DisplayHostName(host),DisplayStatus(host.MAC),DisplayStatus(host.Vendor),Math.Max(48,width-2),sizes),width);
 }
 // Markiert nur sichtbare Suchtreffer und laesst Kuerzungspunkte unmarkiert.
 static bool[] HostSearchHighlights(Host host,int width,int[] sizes) {
  var highlighted=new bool[width];
  if(searchText.Length==0) return highlighted;
  string[] values={host.IP,DisplayHostName(host),DisplayStatus(host.MAC),DisplayStatus(host.Vendor)};
  int gapSpace=Math.Max(0,Math.Max(48,width-2)-sizes.Sum()),columnX=2;
  for(int column=0;column<values.Length;column++) {
   string value=ExportTextValue(values[column]);
   int visible=value.Length<=sizes[column]?value.Length:sizes[column]<4?sizes[column]:sizes[column]-3;
   for(int from=0;from<value.Length;) {
    int match=value.IndexOf(searchText,from,StringComparison.OrdinalIgnoreCase);
    if(match<0) break;
    for(int index=match;index<Math.Min(match+searchText.Length,visible);index++) {
     if(columnX+index<width) highlighted[columnX+index]=true;
    }
    from=match+1;
   }
   columnX+=sizes[column]+gapSpace/3+(column<gapSpace%3?1:0);
  }
  return highlighted;
 }
 // ANSI-Palettenfarben fuer Linux; Suchmarkierungen duerfen nicht durch NO_COLOR verschwinden.
 static string PaletteSequence(ConsoleColor color,bool background) {
  int value=(int)color;
  int ansi=((value&1)<<2)+(value&2)+((value&4)>>2);
  return "\u001b["+((background?40:30)+ansi+((value&8)!=0?60:0))+"m";
 }
 // Schreibt gleichfarbige Abschnitte und bewahrt die Markierung der ausgewaehlten Zeile.
 static void WriteHostRow(string row,Host host,int[] sizes,bool isSelected) {
  if(host.PresenceChange!=0) {
   var presenceForeground=ThemeForeground; var presenceBackground=ThemeBackground;
   bool reverseSelected=!IsWindows && themeIndex==0 && isSelected;
   try {
    if(reverseSelected) Console.Write("\u001b[27m");
    ThemeBackground=isSelected?ConsoleColor.DarkBlue:ConsoleColor.Black;
    ThemeForeground=host.PresenceChange<0?ConsoleColor.Red:ConsoleColor.Green;
    Console.Write(row);
   } finally { ThemeForeground=presenceForeground; ThemeBackground=presenceBackground; if(reverseSelected) Console.Write("\u001b[7m"); }
   return;
  }
  if(searchText.Length==0) { Console.Write(row); return; }
  bool[] highlighted=HostSearchHighlights(host,row.Length,sizes);
  ConsoleColor foreground=ThemeForeground,background=ThemeBackground;
  bool linuxDefault=!IsWindows && themeIndex==0;
  try {
   for(int start=0;start<row.Length;) {
    int end=start+1;
    while(end<row.Length && highlighted[end]==highlighted[start]) end++;
    if(linuxDefault && highlighted[start]) {
     // Reverse video would otherwise turn the match color into its background.
     Console.Write("\u001b[27m"+PaletteSequence(ConsoleColor.DarkBlue,false)+PaletteSequence(isSelected?foreground:background,true));
     try { Console.Write(row.Substring(start,end-start)); }
     finally {
      Console.Write(PaletteSequence(foreground,false)+PaletteSequence(background,true));
      if(isSelected) Console.Write("\u001b[7m");
     }
    } else {
     ThemeForeground=highlighted[start]?(isSelected?ConsoleColor.DarkBlue:MenuBackground):foreground;
     Console.Write(row.Substring(start,end-start));
    }
    start=end;
   }
  } finally { ThemeForeground=foreground; }
 }
 // Beobachtet Fehler weiterlaufender Tasks, deren Wartezeit bereits abgelaufen ist.
 static void Observe(Task t) { t.ContinueWith(x=>{var ignored=x.Exception;},TaskContinuationOptions.OnlyOnFaulted); }
 const int HostPortParallelism=8;
 static readonly SemaphoreSlim hostPortSlots=new SemaphoreSlim(128,128);
 // Begrenzt TCP-Verbindungen aller Hostworker; erfolgreiche Verbindungen raeumen ihren Timeout sofort auf.
 static async Task<bool> ProbeHostPort(string ip,int port,CancellationToken token) {
  return await ProbeHostPortTimeout(ip,port,token,300);
 }
 static async Task<bool> ProbeHostPortTimeout(string ip,int port,CancellationToken token,int timeoutMs) {
  bool acquired=false;
  try {
   await hostPortSlots.WaitAsync(token); acquired=true;
   if(token.IsCancellationRequested) return false;
   using(var tcp=new TcpClient())
   using(var timeout=CancellationTokenSource.CreateLinkedTokenSource(token)) {
    Task connect=tcp.ConnectAsync(ip,port);
    try {
     if(await Task.WhenAny(connect,Task.Delay(timeoutMs,timeout.Token))!=connect) { Observe(connect); return false; }
     await connect;
     return !token.IsCancellationRequested && tcp.Connected;
    } finally { timeout.Cancel(); }
   }
  } catch(SocketException) { return false; }
  catch(OperationCanceledException) { return false; }
  catch(ObjectDisposedException) { return false; }
  finally { if(acquired) hostPortSlots.Release(); }
 }
 // Prueft bis zu acht Ports pro Host gleichzeitig; die Ausgabe bleibt numerisch sortiert.
 static async Task RunHostPortChecks(Host host,int[] numbers,CancellationToken token,Func<int,CancellationToken,Task<bool>> probe) {
  var open=new ConcurrentBag<int>();
  int next=-1;
  var workers=Enumerable.Range(0,Math.Min(HostPortParallelism,numbers.Length)).Select(async worker=>{
   while(!token.IsCancellationRequested) {
    int index=Interlocked.Increment(ref next);
    if(index>=numbers.Length) break;
    if(await probe(numbers[index],token)) open.Add(numbers[index]);
   }
  }).ToArray();
  await Task.WhenAll(workers);
  host.Ports=token.IsCancellationRequested?"Abgebrochen":open.IsEmpty?"Keine im Pruefumfang offen":string.Join(", ",open.OrderBy(port=>port));
 }
 // Prueft einen Host per Ping, ermittelt Metadaten und testet die konfigurierten TCP-Ports.
 static async Task Inspect(uint n,CancellationToken token) {
  await InspectInto(n,token,hosts);
 }
 const int ContinuousPingTimeout=950,ContinuousPortTimeout=450;
 static async Task InspectInto(uint n,CancellationToken token,ConcurrentDictionary<uint,Host> destination,bool continuous=false,bool publishFirstPass=false) {
  try {
   PingReply reply=null;
   int attempts=continuous?(hosts.ContainsKey(n)?3:2):1;
   for(int attempt=0;attempt<attempts && !token.IsCancellationRequested;attempt++) {
    try { using(var ping=new Ping()) reply=await ping.SendPingAsync(IP(n),continuous?ContinuousPingTimeout:700); } catch(PingException) { reply=null; }
    if(reply!=null && reply.Status==IPStatus.Success) break;
    if(attempt+1<attempts) await Task.Delay(100,token);
   }
   if(reply==null || reply.Status!=IPStatus.Success || token.IsCancellationRequested) return;
   var h=new Host { IP=IP(n), Ping=reply.RoundtripTime, ReplyTtl=reply.Options==null?0:reply.Options.Ttl }; destination[n]=h;
   if(publishFirstPass && !hosts.ContainsKey(n)) {
    h.ContinuousOrder=Interlocked.Increment(ref continuousOrder);
    hosts.TryAdd(n,h);
   }
   Task dns=DnsName(h,token);
   Task mac=Task.Run(()=>{ if(!token.IsCancellationRequested) h.MAC=MacAddress(h.IP); else h.MAC="Abgebrochen"; h.Vendor=Vendor(h.MAC); });
   Task tcp=RunHostPortChecks(h,ports,token,(port,stop)=>ProbeHostPortTimeout(h.IP,port,stop,continuous?ContinuousPortTimeout:300));
   await Task.WhenAll(dns,mac,tcp);
  } catch(PingException) {} finally { Interlocked.Increment(ref done); }
 }
 // OS hints are intentionally separate from the scan: only O initiates service probes.
 sealed class OsGuess { public string Family, Evidence; public int Confidence; public OsGuess(string family,string evidence,int confidence=0) { Family=family; Evidence=evidence; Confidence=confidence; } }
 sealed class OsSession {
  public Host Host; public CancellationTokenSource Cancel; public Task Work;
  public volatile OsGuess Result; public volatile string Progress="Dienste werden geprueft ..."; public int Scroll;
 }
 static OsSession osSession;
 static OsGuess GuessOperatingSystem(int ttl,int[] open,string banner) {
  var families=new System.Collections.Generic.List<string>();
  if(!string.IsNullOrEmpty(banner)) {
   if(System.Text.RegularExpressions.Regex.IsMatch(banner,@"(?i)(?:^|[^a-z])(?:OpenSSH_for_Windows|Windows)(?:[^a-z]|$)")) families.Add("Windows");
   foreach(string name in new[]{"Ubuntu","Debian","Linux","FreeBSD","OpenBSD","NetBSD","Darwin"}) {
    if(!System.Text.RegularExpressions.Regex.IsMatch(banner,@"(?i)(?:^|[^a-z])"+name+@"(?:[^a-z]|$)")) continue;
    string family=name=="Ubuntu" || name=="Debian"?"Linux ("+name+")":name=="Darwin"?"macOS/Darwin":name;
    if(name=="Linux" && families.Any(item=>item.StartsWith("Linux (",StringComparison.Ordinal))) continue;
    families.Add(family);
   }
   if(families.Count==1) return new OsGuess(families[0],"SSH: "+banner,2);
   if(families.Count>1) return new OsGuess("Unbekannt (widerspruechliche Hinweise)","SSH: "+banner);
  }
  string evidence="TTL: "+(ttl>0?ttl.ToString():"?")+"; TCP: "+(open.Length==0?"-":string.Join(", ",open));
  if(!string.IsNullOrEmpty(banner)) evidence+="; SSH: "+banner;
  // Neither a common port nor a TTL alone identifies an operating system.
  if(ttl>=100 && ttl<=128 && open.Count(port=>port==135 || port==445 || port==3389)>=2) return new OsGuess("Windows (schwacher Hinweis)",evidence,1);
  if(ttl>=48 && ttl<=64 && open.Contains(22) && !open.Any(port=>port==135 || port==445 || port==3389)) return new OsGuess("Linux/macOS/BSD (schwacher Hinweis)",evidence,1);
  return new OsGuess("Unbekannt (zu wenige Hinweise)",evidence);
 }
 // Reads only the SSH identification, with a total deadline and no authentication.
 static async Task<string> ReadSshIdentification(string ip,int port,CancellationToken token) {
  bool acquired=false;
  using(var deadline=CancellationTokenSource.CreateLinkedTokenSource(token)) {
   deadline.CancelAfter(1200);
   try {
    await hostPortSlots.WaitAsync(deadline.Token); acquired=true;
    using(var client=new TcpClient())
    using(deadline.Token.Register(()=>client.Close())) {
     var connect=client.ConnectAsync(ip,port);
     if(await Task.WhenAny(connect,Task.Delay(Timeout.Infinite,deadline.Token))!=connect) { Observe(connect); return null; }
     await connect;
     var stream=client.GetStream();
     byte[] identification=System.Text.Encoding.ASCII.GetBytes("SSH-2.0-KubScan\r\n");
     await stream.WriteAsync(identification,0,identification.Length,deadline.Token);
     byte[] buffer=new byte[256]; int total=0; var line=new System.Text.StringBuilder();
     while(total<4096 && !deadline.IsCancellationRequested) {
      int count=await stream.ReadAsync(buffer,0,Math.Min(buffer.Length,4096-total),deadline.Token);
      if(count==0) return null;
      total+=count;
      for(int i=0;i<count;i++) {
       char character=(char)buffer[i];
       if(character=='\n') {
        string value=line.ToString().TrimEnd('\r'); line.Clear();
        if(value.StartsWith("SSH-",StringComparison.Ordinal)) {
         if(value.Length>253 || !System.Text.RegularExpressions.Regex.IsMatch(value,@"^SSH-(?:2\.0|1\.99)-[!-~]+(?: [ -~]*)?$")) return null;
         return value;
        }
       } else { if(line.Length>=254) return null; line.Append(character); }
      }
     }
    }
   } catch(SocketException) {} catch(System.IO.IOException) {} catch(OperationCanceledException) {} catch(ObjectDisposedException) {}
   catch(InvalidOperationException) { if(!deadline.IsCancellationRequested) throw; }
   finally { if(acquired) hostPortSlots.Release(); }
  }
  return null;
 }
 // OS probes deliberately stop before authentication: no passwords, NTLM Type 3 or share access.
 static ushort OsWord(byte[] data,int offset) { return (ushort)(data[offset]|data[offset+1]<<8); }
 static uint OsDword(byte[] data,int offset) { return (uint)(data[offset]|data[offset+1]<<8|data[offset+2]<<16|data[offset+3]<<24); }
 static void OsPut(byte[] data,int offset,uint value,int count) { for(int i=0;i<count;i++) data[offset+i]=(byte)(value>>(8*i)); }
 static byte[] OsJoin(params byte[][] parts) { return parts.SelectMany(part=>part).ToArray(); }
 static byte[] OsDer(byte tag,byte[] value) {
  byte[] length=value.Length<128?new[]{(byte)value.Length}:value.Length<256?new[]{(byte)0x81,(byte)value.Length}:new[]{(byte)0x82,(byte)(value.Length>>8),(byte)value.Length};
  return OsJoin(new[]{tag},length,value);
 }
 static byte[] OsNtlmNegotiate() {
  var data=new byte[40]; System.Text.Encoding.ASCII.GetBytes("NTLMSSP\0").CopyTo(data,0);
  OsPut(data,8,1,4); OsPut(data,12,0xe2888235,4); OsPut(data,20,40,4); OsPut(data,28,40,4);
  data[32]=10; OsPut(data,34,19041,2); data[39]=15;
  return data;
 }
 static byte[] OsSpnegoNegotiate() {
  // SPNEGO OID, NegTokenInit, NTLM mechanism OID, and a credential-free Type 1 token.
  byte[] mechanisms=OsDer(0xa0,OsDer(0x30,new byte[]{6,10,0x2b,6,1,4,1,0x82,0x37,2,2,10}));
  return OsDer(0x60,OsJoin(new byte[]{6,6,0x2b,6,1,5,5,2},OsDer(0xa0,OsDer(0x30,OsJoin(mechanisms,OsDer(0xa2,OsDer(4,OsNtlmNegotiate())))))));
 }
 static byte[] OsDerValue(byte[] data,ref int offset,int tag) {
  if(offset+2>data.Length || data[offset++]!=tag) throw new System.IO.InvalidDataException();
  int length=data[offset++];
  if(length>=128) {
   int count=length&127; length=0;
   if(count<1 || count>2 || offset+count>data.Length) throw new System.IO.InvalidDataException();
   while(count-->0) length=(length<<8)|data[offset++];
  }
  if(length>data.Length-offset) throw new System.IO.InvalidDataException();
  byte[] value=data.Skip(offset).Take(length).ToArray(); offset+=length; return value;
 }
 static byte[] OsSpnegoChallenge(byte[] data) {
  if(data.Length>=8 && System.Text.Encoding.ASCII.GetString(data,0,8)=="NTLMSSP\0") return data;
  int offset=0; byte[] response=OsDerValue(data,ref offset,0xa1);
  if(offset!=data.Length) throw new System.IO.InvalidDataException();
  offset=0; byte[] sequence=OsDerValue(response,ref offset,0x30);
  if(offset!=response.Length) throw new System.IO.InvalidDataException();
  offset=0; byte[] token=null;
  while(offset<sequence.Length) {
   int tag=sequence[offset]; byte[] value=OsDerValue(sequence,ref offset,tag);
   if(tag==0xa2) {
    if(token!=null) throw new System.IO.InvalidDataException();
    int cursor=0; token=OsDerValue(value,ref cursor,4);
    if(cursor!=value.Length) throw new System.IO.InvalidDataException();
   }
  }
  return token;
 }
 static OsGuess ParseOsNtlm(byte[] data,string source) {
  if(data==null || data.Length<56 || System.Text.Encoding.ASCII.GetString(data,0,8)!="NTLMSSP\0" || OsDword(data,8)!=2 || (OsDword(data,20)&0x02000000)==0) return null;
  foreach(int field in new[]{12,40}) {
   int length=OsWord(data,field); uint offset=OsDword(data,field+4);
   if(OsWord(data,field+2)<length || (length>0 && (offset<56 || offset>data.Length || length>data.Length-offset))) return null;
  }
  // Samba commonly reports 6.1.0. A zero build or a missing version is not Windows evidence.
  int major=data[48],minor=data[49],build=OsWord(data,50);
  if(major<5 || major>10 || minor>3 || build==0 || data[52]!=0 || data[53]!=0 || data[54]!=0 || data[55]!=15) return null;
  return new OsGuess("Windows",source+"/NTLM: "+major+"."+minor+"."+build,2);
 }
 static byte[] OsSmbRequest(int command,int messageId,byte[] body) {
  var header=new byte[64]; header[0]=0xfe; header[1]=83; header[2]=77; header[3]=66;
  OsPut(header,4,64,2); OsPut(header,12,(uint)command,2); OsPut(header,14,1,2); OsPut(header,24,(uint)messageId,4);
  return OsJoin(header,body);
 }
 static void OsValidateSmb(byte[] data,int command,int messageId,uint status) {
  if(data.Length<64 || data[0]!=0xfe || data[1]!=83 || data[2]!=77 || data[3]!=66 || OsWord(data,4)!=64 || OsWord(data,12)!=command || OsDword(data,8)!=status || (OsDword(data,16)&3)!=1 || OsDword(data,20)!=0 || OsDword(data,24)!=messageId || OsDword(data,28)!=0) throw new System.IO.InvalidDataException();
 }
 static async Task OsWriteSmb(System.IO.Stream stream,byte[] packet,CancellationToken token) {
  byte[] frame=OsJoin(new[]{(byte)0,(byte)(packet.Length>>16),(byte)(packet.Length>>8),(byte)packet.Length},packet);
  await stream.WriteAsync(frame,0,frame.Length,token);
 }
 static async Task<byte[]> OsReadSmb(System.IO.Stream stream,CancellationToken token) {
  var header=new byte[4]; await ReadNamePacket(stream,header,token);
  int length=header[1]<<16|header[2]<<8|header[3];
  if(header[0]!=0 || length<64 || length>65536) throw new System.IO.InvalidDataException();
  var data=new byte[length]; await ReadNamePacket(stream,data,token); return data;
 }
 static async Task<OsGuess> OsSmbExchange(System.IO.Stream stream,CancellationToken token) {
  // Offer SMB 2.0.2 through 3.1.1, including the mandatory SHA-512 preauthentication context.
  var negotiate=new byte[94]; OsPut(negotiate,0,36,2); OsPut(negotiate,2,5,2); OsPut(negotiate,4,1,2);
  OsPut(negotiate,28,112,4); OsPut(negotiate,32,1,2);
  OsPut(negotiate,48,1,2); OsPut(negotiate,50,38,2); OsPut(negotiate,56,1,2); OsPut(negotiate,58,32,2); OsPut(negotiate,60,1,2);
  Guid.NewGuid().ToByteArray().CopyTo(negotiate,62); Guid.NewGuid().ToByteArray().CopyTo(negotiate,78);
  Guid.NewGuid().ToByteArray().CopyTo(negotiate,12);
  int[] dialects={0x0202,0x0210,0x0300,0x0302,0x0311};
  for(int i=0;i<dialects.Length;i++) OsPut(negotiate,36+i*2,(uint)dialects[i],2);
  await OsWriteSmb(stream,OsSmbRequest(0,0,negotiate),token);
  byte[] response=await OsReadSmb(stream,token); OsValidateSmb(response,0,0,0);
  if(response.Length<128 || OsWord(response,64)!=65 || !dialects.Contains((int)OsWord(response,68))) throw new System.IO.InvalidDataException();
  byte[] security=OsSpnegoNegotiate(),setup=new byte[24];
  OsPut(setup,0,25,2); setup[3]=1; OsPut(setup,12,88,2); OsPut(setup,14,(uint)security.Length,2);
  await OsWriteSmb(stream,OsSmbRequest(1,1,OsJoin(setup,security)),token);
  response=await OsReadSmb(stream,token); OsValidateSmb(response,1,1,0xc0000016); // STATUS_MORE_PROCESSING_REQUIRED
  if(response.Length<72 || OsWord(response,64)!=9) throw new System.IO.InvalidDataException();
  int offset=OsWord(response,68),length=OsWord(response,70);
  if(offset<72 || length==0 || offset>response.Length || length>response.Length-offset) throw new System.IO.InvalidDataException();
  return ParseOsNtlm(OsSpnegoChallenge(response.Skip(offset).Take(length).ToArray()),"SMB");
 }
 static async Task<byte[]> OsReadDer(System.IO.Stream stream,CancellationToken token) {
  var header=new byte[2]; await ReadNamePacket(stream,header,token);
  if(header[0]!=0x30) throw new System.IO.InvalidDataException();
  int length=header[1];
  if(length>=128) {
   int count=length&127; if(count<1 || count>2) throw new System.IO.InvalidDataException();
   var bytes=new byte[count]; await ReadNamePacket(stream,bytes,token); length=0;
   foreach(byte b in bytes) length=(length<<8)|b;
  }
  if(length==0 || length>32768) throw new System.IO.InvalidDataException();
  var data=new byte[length]; await ReadNamePacket(stream,data,token); return data;
 }
 static byte[] OsCredSspChallenge(byte[] data) {
  int offset=0; byte[] tokens=null;
  while(offset<data.Length) {
   int tag=data[offset]; byte[] value=OsDerValue(data,ref offset,tag);
   if(tag==0xa4) return null; // CredSSP errorCode, never reinterpret as an OS indication.
   if(tag==0xa1) {
    if(tokens!=null) throw new System.IO.InvalidDataException();
    tokens=value;
   }
  }
  if(tokens==null) return null;
  foreach(int tag in new[]{0x30,0x30,0xa0,4}) {
   offset=0; byte[] value=OsDerValue(tokens,ref offset,tag);
   if(offset!=tokens.Length) throw new System.IO.InvalidDataException();
   tokens=value;
  }
  return OsSpnegoChallenge(tokens);
 }
 static async Task<OsGuess> OsRdpExchange(System.IO.Stream stream,string ip,CancellationToken token) {
  byte[] request={3,0,0,19,14,0xe0,0,0,0,0,0,1,0,8,0,3,0,0,0}; // TLS or CredSSP
  await stream.WriteAsync(request,0,request.Length,token);
  var header=new byte[4]; await ReadNamePacket(stream,header,token);
  int length=header[2]<<8|header[3];
  if(header[0]!=3 || header[1]!=0 || length!=19) return null;
  var response=new byte[15]; await ReadNamePacket(stream,response,token);
  if(response[0]!=14 || response[1]!=0xd0 || response[6]!=0 || response[7]!=2 || OsWord(response,9)!=8 || OsDword(response,11)!=2) return null;
  // Self-signed RDP certificates are common. This connection sends no identity or credentials;
  // its unauthenticated peer claims remain estimates, never a verified host identity.
  using(var tls=new System.Net.Security.SslStream(stream,true,(sender,certificate,chain,errors)=>true)) {
   await tls.AuthenticateAsClientAsync(ip,null,System.Security.Authentication.SslProtocols.Tls12,false);
   byte[] payload=OsDer(0x30,OsJoin(OsDer(0xa0,new byte[]{2,1,6}),OsDer(0xa1,OsDer(0x30,OsDer(0x30,OsDer(0xa0,OsDer(4,OsNtlmNegotiate())))))));
   await tls.WriteAsync(payload,0,payload.Length,token);
   return ParseOsNtlm(OsCredSspChallenge(await OsReadDer(tls,token)),"RDP");
  }
 }
 static async Task<OsGuess> ReadOsService(string ip,int port,bool rdp,CancellationToken token) {
  bool acquired=false; string source=rdp?"RDP":"SMB";
  using(var deadline=CancellationTokenSource.CreateLinkedTokenSource(token)) {
   deadline.CancelAfter(2500);
   try {
    await hostPortSlots.WaitAsync(deadline.Token); acquired=true;
    using(var client=new TcpClient())
    using(deadline.Token.Register(()=>client.Close())) {
     var connect=client.ConnectAsync(ip,port);
     if(await Task.WhenAny(connect,Task.Delay(Timeout.Infinite,deadline.Token))!=connect) { Observe(connect); return new OsGuess("",source+": Zeitlimit erreicht"); }
     await connect;
     var result=rdp?await OsRdpExchange(client.GetStream(),ip,deadline.Token):await OsSmbExchange(client.GetStream(),deadline.Token);
     return result??new OsGuess("",source+": keine OS-Angabe");
    }
   } catch(SocketException) {} catch(System.IO.InvalidDataException) {} catch(System.IO.IOException) {} catch(OperationCanceledException) {} catch(ObjectDisposedException) {} catch(System.Security.Authentication.AuthenticationException) {}
   catch(InvalidOperationException) { if(!deadline.IsCancellationRequested) throw; }
   finally { if(acquired) hostPortSlots.Release(); }
   return new OsGuess("",source+(deadline.IsCancellationRequested?": Zeitlimit erreicht":": keine OS-Angabe"));
  }
 }
 static string OsFamilyKey(string family) {
  if(family.StartsWith("Linux",StringComparison.Ordinal) && !family.Contains("/")) return "Linux";
  if(family.StartsWith("Windows",StringComparison.Ordinal)) return "Windows";
  if(family=="Mac OS X" || family=="Mac OS" || family=="Darwin" || family=="macOS/Darwin") return "macOS/Darwin";
  if(family=="FreeBSD" || family=="OpenBSD" || family=="NetBSD") return family;
  return "";
 }
 static OsGuess CombineOsGuesses(OsGuess fallback,OsGuess[] probes) {
  var candidates=probes.Where(p=>p!=null && p.Confidence>0 && OsFamilyKey(p.Family)!="").ToArray();
  var sources=probes.Where(p=>p!=null && !string.IsNullOrEmpty(p.Evidence)).Select(p=>p.Evidence).ToList();
  if(fallback!=null) sources.Add(fallback.Evidence);
  string evidence=string.Join("\n",sources.Distinct());
  bool conflict=probes.Any(p=>p!=null && p.Family=="Unbekannt (widerspruechliche Hinweise)");
  // Conflicting service claims are retained even if their confidence differs.
  if(conflict || candidates.Select(p=>OsFamilyKey(p.Family)).Distinct().Count()>1) return new OsGuess("Unbekannt (widerspruechliche Hinweise)",evidence);
  if(candidates.Length==0) return new OsGuess(fallback==null?"Unbekannt (zu wenige Hinweise)":fallback.Family,evidence,fallback==null?0:fallback.Confidence);
  var best=candidates.OrderByDescending(p=>p.Confidence).ThenByDescending(p=>p.Family.Length).First();
  return new OsGuess(best.Family,evidence,best.Confidence);
 }
 static async Task DetectOperatingSystem(OsSession session,int[] open) {
  var token=session.Cancel.Token;
  OsGuess fallback=GuessOperatingSystem(session.Host.ReplyTtl,open,null);
  session.Result=fallback;
  try {
   var ssh=ReadSshIdentification(session.Host.IP,22,token);
   var smb=ReadOsService(session.Host.IP,445,false,token);
   var rdp=ReadOsService(session.Host.IP,3389,true,token);
   await Task.WhenAll(ssh,(Task)smb,rdp);
   token.ThrowIfCancellationRequested();
   OsGuess sshGuess=GuessOperatingSystem(0,new int[0],await ssh);
   var probes=new System.Collections.Generic.List<OsGuess> { await smb,await rdp };
   if(await ssh!=null) probes.Insert(0,sshGuess);
   session.Result=CombineOsGuesses(fallback,probes.ToArray());
  } catch(OperationCanceledException) {}
  catch(Exception error) {
   // Keep a failed background probe from leaving an endless progress dialog.
   if(!token.IsCancellationRequested) session.Result=new OsGuess("Unbekannt (zu wenige Hinweise)","OS: "+error.GetType().Name+"\n"+fallback.Evidence);
  } finally { session.Progress=null; }
 }
 static void CloseOsDetection() {
  var session=osSession; osSession=null;
  if(session!=null) { session.Cancel.Cancel(); session.Work.ContinueWith(completed=>session.Cancel.Dispose()); }
 }
 static void OpenOsDetection() {
  var list=SortedHosts();
  if(list.Length==0) { dialogTitle="HINWEIS"; dialogMessage="Kein Eintrag ausgewaehlt."; return; }
  CloseOsDetection();
  var host=list[Math.Max(0,Math.Min(selected,list.Length-1))];
  var session=new OsSession { Host=host,Cancel=new CancellationTokenSource() };
  osSession=session; dialogTitle="Betriebssystem (Vermutung)"; dialogMessage="Wird ermittelt ...";
  session.Work=Task.Run(()=>DetectOperatingSystem(session,OpenPortNumbers(host)));
 }
 static int[] OpenPortNumbers(Host host) {
  return (host.Ports??"").Split(',').Select(value=>{ int port; return int.TryParse(value.Trim(),out port)?port:0; }).Where(port=>port>0 && port<=65535).ToArray();
 }
 static void UpdateOsDialog() {
  var session=osSession; if(session==null) return;
  var result=session.Result;
  if(result==null) { dialogMessage=session.Host.IP+"\n"+T("Wird ermittelt ..."); return; }
  int width=Math.Max(30,Math.Min(76,Console.WindowWidth-12));
  string confidence=result.Confidence>=2?"Sicherheit: starker Hinweis":result.Confidence==1?"Sicherheit: schwacher Hinweis":"Sicherheit: unbestimmt";
  var lines=new System.Collections.Generic.List<string> { session.Host.IP,T(result.Family),T(confidence) };
  if(session.Progress!=null) lines.Add(T(session.Progress));
  lines.Add(T("Grundlage:"));
  foreach(string source in result.Evidence.Split('\n')) {
   string evidence=ExportTextValue(T(source));
   for(int start=0;start<evidence.Length;start+=width) lines.Add(evidence.Substring(start,Math.Min(width,evidence.Length-start)));
  }
  lines.Add(T("Keine sichere Identifikation."));
  int visible=Math.Max(3,Console.WindowHeight-9);
  session.Scroll=Math.Max(0,Math.Min(session.Scroll,Math.Max(0,lines.Count-visible)));
  var page=lines.Skip(session.Scroll).Take(visible).ToList();
  if(lines.Count>visible) page.Add(T("Pfeile / Bild auf/ab: Details scrollen"));
  dialogMessage=string.Join("\n",page);
 }
 // Wiederholt den zuletzt gestarteten Bereich oder meldet einen fehlenden vorherigen Scan.
 static void RepeatScan() {
  if(!hasScan) {
   dialogTitle="FEHLER";
   dialogMessage="Noch kein Scan zum Wiederholen vorhanden.";
   return;
  }
  Start(scannedSubnet);
 }
 static volatile bool continuousMode;
 static bool continuousList;
 static long continuousOrder;
 static readonly System.Collections.Generic.HashSet<uint> continuousBaseline=new System.Collections.Generic.HashSet<uint>();
 static int continuousRounds;
 static void MergeContinuousResults(ConcurrentDictionary<uint,Host> results) {
  bool first=continuousRounds==0;
  if(first) { continuousBaseline.Clear(); foreach(uint address in results.Keys) continuousBaseline.Add(address); }
  foreach(var pair in hosts.ToArray()) {
   Host fresh;
   if(!results.TryGetValue(pair.Key,out fresh)) {
    if(first) { pair.Value.MissedRounds=0; pair.Value.PresenceChange=0; }
    else if(++pair.Value.MissedRounds>=2) pair.Value.PresenceChange=-1;
    continue;
   }
   var host=pair.Value;
   if(host.PresenceChange<0) host.Returned=true;
   host.MissedRounds=0;
   host.PresenceChange=host.Returned || !continuousBaseline.Contains(pair.Key)?1:0;
   host.Ping=fresh.Ping; host.ReplyTtl=fresh.ReplyTtl; host.DNS=fresh.DNS; host.NameSource=fresh.NameSource;
   host.MAC=fresh.MAC; host.Vendor=fresh.Vendor; host.Ports=fresh.Ports;
  }
  foreach(var pair in results.OrderBy(pair=>pair.Key)) {
   if(hosts.ContainsKey(pair.Key)) continue;
   pair.Value.PresenceChange=continuousBaseline.Contains(pair.Key)?0:1; pair.Value.ContinuousOrder=++continuousOrder;
   hosts.TryAdd(pair.Key,pair.Value);
  }
  Interlocked.Increment(ref continuousRounds);
 }
 static void StartContinuous(string input) {
  if(continuousMode) { if(cancel!=null) cancel.Cancel(); return; }
  if(scan!=null && !scan.IsCompleted) { message="Scan laeuft. Esc bricht ab."; return; }
  string target=hasScan?scannedSubnet:(input??"").Trim();
  if(target.Length>0 && !target.Contains("/") && !target.Contains("-")) target+="/32";
  uint[] addresses;
  try { addresses=Parse(target); } catch(ArgumentException error) { dialogTitle="FEHLER"; dialogMessage=error.Message; return; }
  StartContinuousScan(target,addresses);
 }
 static void StartContinuousScan(string target,uint[] addresses) {
  continuousOrder=0; continuousRounds=0; continuousBaseline.Clear();
  foreach(var host in hosts.Values) { host.PresenceChange=0; host.MissedRounds=0; host.Returned=false; }
  foreach(var host in hosts.Values) host.ContinuousOrder=0;
  foreach(var host in SortedHosts()) host.ContinuousOrder=++continuousOrder;
  foreach(var pair in hosts.ToArray().OrderBy(pair=>pair.Key)) if(pair.Value.ContinuousOrder==0) pair.Value.ContinuousOrder=++continuousOrder;
  continuousList=true; continuousMode=true; hasScan=true; scannedSubnet=ScanTargetLabel(target,addresses);
  cancel=new CancellationTokenSource(); var token=cancel.Token;
  total=addresses.Length; done=0; message="Continuous";
  scan=Task.Run(async ()=> {
   try {
    while(!token.IsCancellationRequested) {
     var results=new ConcurrentDictionary<uint,Host>(); int next=-1; done=0;
     bool firstPass=continuousRounds==0;
     await Task.WhenAll(Enumerable.Range(0,Math.Min(64,addresses.Length)).Select(async worker=> {
      while(!token.IsCancellationRequested) {
       int index=Interlocked.Increment(ref next); if(index>=addresses.Length) break;
       await InspectInto(addresses[index],token,results,true,firstPass);
      }
     }));
     if(token.IsCancellationRequested) break;
     MergeContinuousResults(results);
     await Task.Delay(600,token);
    }
   } catch(OperationCanceledException) {} finally { continuousMode=false; }
  });
 }
 // Validiert den Bereich, setzt den Scanstatus zurueck und startet bis zu 64 Hostworker.
 static void Start(string input) {
  input=(input??"").Trim();
  if(string.IsNullOrWhiteSpace(input)) {
   dialogTitle="FEHLER";
   dialogMessage="Kein Scanbereich eingegeben.";
   message=dialogMessage;
   return;
  }
  if(scan!=null && !scan.IsCompleted) { message="Scan laeuft. Esc bricht ab."; return; }
  if(!input.Contains("/") && !input.Contains("-")) {
   try { Parse(input+"/32"); }
   catch(ArgumentException e) { dialogTitle="FEHLER"; dialogMessage=e.Message; return; }
   cidrInput=input; cidrIndex=8;
   return;
  }
  uint[] addresses; try { addresses=Parse(input); } catch(ArgumentException e) { message=e.Message; return; }
  StartIpScan(input,addresses);
 }
 static void StartIpScan(string input,uint[] addresses) {
  scannedSubnet=ScanTargetLabel(input,addresses);
  hasScan=true; detailHost=null;
  searchText=""; searchEditing=false;
  continuousList=false;
  hosts.Clear(); done=0; total=addresses.Length; selected=0; cancel=new CancellationTokenSource(); var token=cancel.Token;
  message="Scan laeuft";
  scan=Task.Run(async()=>{
   int index=-1;
   await Task.WhenAll(Enumerable.Range(0,Math.Min(64,total)).Select(worker=>Task.Run(async()=>{
    while(!token.IsCancellationRequested) { int i=Interlocked.Increment(ref index); if(i>=addresses.Length) break; await Inspect(addresses[i],token); }
   })).ToArray());
  });
 }
 const ConsoleColor MenuBackground=ConsoleColor.DarkBlue;
 // Berechnet einen begrenzten Fortschrittswert ohne Ganzzahlueberlauf bei der Multiplikation.
 static int ProgressValue(int completed,int count,int scale) {
  if(count<=0) return 0;
  return (int)((long)Math.Max(0,Math.Min(completed,count))*scale/count);
 }
 // Zeichnet Zaehler, Prozentwert und Fortschrittsbalken fuer den Hostscan.
 static void DrawProgress(int row,int width,string state,int completed,int count,int hostCount) {
  string prefix=state+" | "+completed+"/"+count+" ";
  string suffix=" "+ProgressValue(completed,count,100)+"% | Hosts: "+hostCount;
  int barWidth=Math.Max(1,Math.Min(30,width-prefix.Length-suffix.Length));
  Line(row,prefix+new string(' ',barWidth)+suffix,width);
  int filled=ProgressValue(completed,count,barWidth);
  ConsoleColor foreground=ThemeForeground,background=ThemeBackground;
  try {
   Console.SetCursorPosition(prefix.Length,row);
   ThemeForeground=ConsoleColor.Black;
   ThemeBackground=MenuBackground;
   if(filled>0) {
    Console.Write(new string(' ',filled-1));
    ThemeBackground=ConsoleColor.White;
    Console.Write(' ');
   }
  } finally {
   ThemeForeground=foreground;
   ThemeBackground=background;
  }
 }
 // Schreibt eine Konsolenzeile mit fester Breite und entfernt dabei alte Restzeichen.
 static void Line(int row,string text,int width) { Console.SetCursorPosition(0,row); Console.Write(text.Length>width?text.Substring(0,width):text.PadRight(width)); }
 static ConsoleColor HeadingColor { get { return (ThemeBackground==ConsoleColor.DarkBlue || ThemeBackground==ConsoleColor.DarkRed)?ConsoleColor.Cyan:ConsoleColor.DarkBlue; } }
 // Schreibt eine Ueberschrift mit Theme-Akzent und stellt die Ausgangsfarbe wieder her.
 static void WriteHeading(string text) {
  if(themeIndex==0) { Console.Write(text); return; }
  var foreground=ThemeForeground;
  try { ThemeForeground=HeadingColor; Console.Write(text); }
  finally { ThemeForeground=foreground; }
 }
 // Positioniert und schreibt eine Ueberschriftszeile in der vorgegebenen Breite.
 static void HeadingLine(int row,string text,int width) {
  Console.SetCursorPosition(0,row); WriteHeading(Cell(text,width));
 }
 // Verwendet eine zum Popup-Hintergrund passende Akzentfarbe fuer den Titel.
 static void WritePopupHeading(string line) {
  if(line.Length<2) { WriteHeading(line); return; }
  Console.Write(line.Substring(0,1));
  WriteHeading(line.Substring(1,line.Length-2));
  Console.Write(line.Substring(line.Length-1));
 }
 // Zeichnet Eingabe- und Suchzeilen mit den vorgesehenen Markierungen.
 static void SearchLine(int row,string text,int width) {
  if(!text.StartsWith(T("Suchen"),StringComparison.Ordinal)) { Line(row,text,width); return; }
  string line=Cell(text,width);
  int labelWidth=Math.Min(T("Suchen:").Length,line.Length);
  ConsoleColor foreground=ThemeForeground;
  try {
   Console.SetCursorPosition(0,row);
   ThemeForeground=MenuBackground;
   Console.Write(line.Substring(0,labelWidth));
   ThemeForeground=foreground;
   Console.Write(line.Substring(labelWidth));
  } finally { ThemeForeground=foreground; }
 }
 [StructLayout(LayoutKind.Explicit,Size=20)]
 struct ConsoleInputRecord {
  [FieldOffset(0)] public ushort EventType;
  [FieldOffset(4)] public int KeyDown;
  [FieldOffset(8)] public ushort RepeatCount;
  [FieldOffset(10)] public ushort VirtualKey;
  [FieldOffset(14)] public char Character;
  [FieldOffset(16)] public uint ControlState;
  [FieldOffset(4)] public short MouseX;
  [FieldOffset(6)] public short MouseY;
  [FieldOffset(8)] public uint MouseButtons;
  [FieldOffset(16)] public uint MouseFlags;
 }
 // Native Konsolenereignisse; Eingabe- und Ausgabemodus werden vor Aenderungen gesichert.
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr GetStdHandle(int kind);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetConsoleMode(IntPtr handle,out uint mode);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetConsoleMode(IntPtr handle,uint mode);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetNumberOfConsoleInputEvents(IntPtr handle,out uint count);
 [DllImport("kernel32.dll",EntryPoint="ReadConsoleInputW",SetLastError=true)] static extern bool ReadConsoleInput(IntPtr handle,out ConsoleInputRecord record,uint count,out uint read);
 static bool mouseLeftDown;
 static ConsoleKeyInfo repeatedKey;
 static int keyRepeats;
 // Ordnet Mausklicks ausschliesslich den sichtbaren Schaltflaechen der untersten Zeile zu.
 static int MenuHitTest(int x,int y,int width,int height) {
  if(width<89 || height<headerLines.Length+15 || y!=height-1 || x<0 || x>=width) return -1;
  if(listenMode) return ArpMenuHitTest(x,width);
  int fieldWidth=Math.Max(0,(width-21)/MenuLabels.Length);
  int extra=Math.Max(0,width-21-fieldWidth*MenuLabels.Length),left=0;
  for(int i=0;i<MenuLabels.Length;i++) {
   int end=left+(i==9?3:2)+fieldWidth;
   if(x>=left && x<end) return mdnsMode && i==2?-1:i;
   left=end+(i+1)*extra/MenuLabels.Length-i*extra/MenuLabels.Length;
  }
  return -1;
 }
 // Uebersetzt Windows-Tastatur- und Menue-Mausereignisse in gemeinsame Tastenaktionen.
 static bool TryReadConsoleKey(IntPtr handle,out ConsoleKeyInfo key) {
  if(!IsWindows) return TryReadLinuxKey(out key);
  key=default(ConsoleKeyInfo);
  if(keyRepeats>0) { key=repeatedKey; keyRepeats--; return true; }
  uint count,read;
  while(GetNumberOfConsoleInputEvents(handle,out count) && count>0) {
   ConsoleInputRecord record;
   if(!ReadConsoleInput(handle,out record,1,out read) || read==0) return false;
   if(record.EventType==1 && record.KeyDown!=0) {
    if(record.VirtualKey==16 || record.VirtualKey==17 || record.VirtualKey==18) continue;
    key=new ConsoleKeyInfo(record.Character,(ConsoleKey)record.VirtualKey,(record.ControlState&16)!=0,(record.ControlState&3)!=0,(record.ControlState&12)!=0);
    repeatedKey=key; keyRepeats=Math.Max(0,(int)record.RepeatCount-1);
    return true;
   }
   if(record.EventType==2) {
    bool leftDown=(record.MouseButtons&1)!=0;
    bool clicked=leftDown && !mouseLeftDown && (record.MouseFlags==0 || record.MouseFlags==2);
    mouseLeftDown=leftDown;
    if(!clicked) continue;
    int index=MenuHitTest(record.MouseX-Console.WindowLeft,record.MouseY-Console.WindowTop,Console.WindowWidth-1,Console.WindowHeight);
    if(index<0) continue;
    key=new ConsoleKeyInfo('\0',MenuAction(index),false,false,false);
    return true;
   }
  }
  return false;
 }

 static readonly string[] ArpMenuKeys={"F1","F2","F3","F4","F7","F9/Esc","F10"};
 static readonly ConsoleKey[] ArpMenuActions={ConsoleKey.F1,ConsoleKey.F2,ConsoleKey.F3,ConsoleKey.F4,ConsoleKey.F7,ConsoleKey.F9,ConsoleKey.F10};
 // Fill the row with evenly sized colored label fields, like the mDNS menu.
 // Only one uncolored separator remains between adjacent buttons.
 static int[] ArpMenuFieldWidths(int width) {
  int count=ArpMenuKeys.Length;
  int available=Math.Max(0,width-ArpMenuKeys.Sum(k=>k.Length)-count-(count-1));
  return Enumerable.Range(0,count).Select(i=>available/count+(i<available%count?1:0)).ToArray();
 }
 static string[] ArpMenuLabels(int width) {
  string[] labels=English?new[]{"Help","Resume","New capture","Adapter","Search","Stop","Quit"}:
   new[]{"Hilfe","Fortsetzen","Neuer Mitschnitt","Adapter","Suche","Stopp","Ende"};
  string[] compact=English?new[]{"Help","Go","New","NIC","Find","Stop","Quit"}:
   new[]{"Hilfe","Los","Neu","NIC","Suche","Stop","Ende"};
  var fields=ArpMenuFieldWidths(width);
  return labels.Select((label,i)=>label.Length>fields[i]?compact[i]:label).ToArray();
 }
 static int[] ArpMenuStarts(int width) {
  var fields=ArpMenuFieldWidths(width); var starts=new int[fields.Length]; int left=0;
  for(int i=0;i<fields.Length;i++) {
   starts[i]=left; left+=ArpMenuKeys[i].Length+1+fields[i]+1;
  }
  return starts;
 }
 static int ArpMenuHitTest(int x,int width) {
  var fields=ArpMenuFieldWidths(width); var starts=ArpMenuStarts(width);
  for(int i=0;i<fields.Length;i++) {
   int end=starts[i]+ArpMenuKeys[i].Length+1+fields[i];
   if(x>=starts[i] && x<end) return i;
  }
  return -1;
 }
 static ConsoleKey MenuAction(int index) { return listenMode?ArpMenuActions[index]:(ConsoleKey)((int)ConsoleKey.F1+index); }
 static void DrawArpMenu(int row,int width) {
  var labels=ArpMenuLabels(width); var starts=ArpMenuStarts(width); var fields=ArpMenuFieldWidths(width);
  ConsoleColor fg=ThemeForeground,bg=ThemeBackground;
  try {
   // Clear first, including old longer labels and the spaces between buttons.
   ThemeForeground=ConsoleColor.Gray; ThemeBackground=ConsoleColor.Black;
   Console.SetCursorPosition(0,row); Console.Write(new string(' ',width));
   for(int i=0;i<labels.Length;i++) {
    Console.SetCursorPosition(starts[i],row);
    ThemeForeground=ConsoleColor.Gray; ThemeBackground=ConsoleColor.Black;
    Console.Write(ArpMenuKeys[i]+" ");
    SetMenuLabelColors();
    Console.Write(Cell(labels[i],fields[i]));
   }
  } finally { ThemeForeground=fg; ThemeBackground=bg; }
 }
 static System.Collections.Generic.Dictionary<uint,string> PktAdapterLabels(PktSource[] sources,ArpNicInfo[] nics) {
  var labels=new System.Collections.Generic.Dictionary<uint,string>();
  var conflicting=new System.Collections.Generic.HashSet<uint>();
  foreach(var source in sources) {
   string label=PktAdapterOption(source,nics).Label;
   foreach(uint id in new[]{source.Id,source.SecondaryId}.Where(id=>id!=0)) {
    string previous;
    if(labels.TryGetValue(id,out previous) && previous!=label) conflicting.Add(id);
    labels[id]=label;
   }
  }
  foreach(uint id in conflicting) labels.Remove(id);
  return labels;
 }

 static readonly string[] MenuLabels={"Hilfe","Scan","Continuous","Dauerping","Export CSV","Export TXT","Suche","OUI-Update","Abbruch","Ende"};
 // One Dark Pro: blaue Schrift auf dunkler Menueflaeche wie in der Referenz.
 static void SetMenuLabelColors() {
  if(themeIndex==DefaultThemeIndex) {
   ThemeBackground=ConsoleColor.DarkBlue; ThemeForeground=ConsoleColor.Blue;
   if(trueColorEnabled) Console.Write(RgbSequence(0x21252b,true));
  } else {
   ThemeForeground=themeIndex==0?ConsoleColor.White:ConsoleColor.Black;
   ThemeBackground=themeIndex==0?MenuBackground:ConsoleColor.DarkMagenta;
  }
 }
 // Waehlt eine zur Fensterbreite passende Beschriftung einer Funktionstaste.
 static string MenuCaption(int index,int width) {
  string label=mdnsMode && index==1?T("Rescan"):
   (mdnsMode && index==2) || ((mdnsMode || listenMode) && (index==3 || index==4 || index==5 || index==7))?"":T(MenuLabels[index]);
  if(label.Length>width) {
   if(index==2 && !mdnsMode) label="Cont.";
   if(index==3) label="Ping";
   else if(index==4) label="ExpCSV";
   else if(index==5) label="ExpTXT";
   else if(index==7) label="OUIUpd";
   else if(index==8) label=T("Stopp");
  }
  return Cell(label,width);
 }
 // Verteilt und zeichnet die klickbaren Funktionstasten am unteren Fensterrand.
 static void DrawMenu(int row,int width) {
  if(listenMode) { DrawArpMenu(row,width); return; }
  ConsoleColor foreground=ThemeForeground,background=ThemeBackground;
  int fieldWidth=Math.Max(0,(width-21)/MenuLabels.Length);
  int extra=Math.Max(0,width-21-fieldWidth*MenuLabels.Length);
  try {
   Console.SetCursorPosition(0,row);
   for(int i=0;i<MenuLabels.Length;i++) {
    string key="F"+(i+1).ToString(System.Globalization.CultureInfo.InvariantCulture);
    ThemeForeground=ConsoleColor.Gray;
    ThemeBackground=ConsoleColor.Black;
    Console.Write(key);
    SetMenuLabelColors();
    Console.Write(MenuCaption(i,fieldWidth));
    ThemeBackground=ConsoleColor.Black;
    Console.Write(new string(' ',(i+1)*extra/MenuLabels.Length-i*extra/MenuLabels.Length));
   }
  } finally {
   ThemeForeground=foreground;
   ThemeBackground=background;
  }
 }
 sealed class PortScanSession {
  public Host Host;
  public string Input="",Error="";
  public bool Editing;
  public bool Udp;
  public readonly ConcurrentDictionary<int,string> UdpResults=new ConcurrentDictionary<int,string>();
  public volatile bool Running;
  public int Done,Total,Scroll;
  public readonly CancellationTokenSource Cancel=new CancellationTokenSource();
  public readonly ConcurrentDictionary<int,bool> Open=new ConcurrentDictionary<int,bool>();
  public Task Worker;
  public string[] Rendered;
  public int X,Y;
 }
 static PortScanSession portScan;
 // Validiert einzelne Ports und Bereiche und entfernt doppelte Portnummern.
 internal static int[] ParsePortSelection(string input) {
  var result=new System.Collections.Generic.SortedSet<int>();
  foreach(string item in (input??"").Split(new[]{',',';',' '},StringSplitOptions.RemoveEmptyEntries)) {
   string[] range=item.Split('-'); int first,last;
   if(range.Length>2 || !int.TryParse(range[0],out first) || first<1 || first>65535) throw new ArgumentException("Ports: 1-65535, z.B. 22,80,443,8000-8100");
   last=first;
   if(range.Length==2 && (!int.TryParse(range[1],out last) || last<first || last>65535)) throw new ArgumentException("Ungueltiger Portbereich: "+item);
   for(int number=first;number<=last;number++) result.Add(number);
  }
  if(result.Count==0) throw new ArgumentException("Bitte mindestens einen Port eingeben.");
  return result.ToArray();
 }
 // Liefert einen ueblichen Dienstnamen anhand der Portnummer ohne Diensterkennung.
 static string PortService(int port) {
  switch(port) {
   case 20: return "FTP-Daten"; case 21: return "FTP"; case 22: return "SSH"; case 23: return "Telnet";
   case 25: return "SMTP"; case 53: return "DNS"; case 80: return "HTTP"; case 110: return "POP3";
   case 111: return "RPCbind"; case 135: return "Microsoft RPC"; case 139: return "NetBIOS"; case 143: return "IMAP";
   case 389: return "LDAP"; case 443: return "HTTPS"; case 445: return "SMB"; case 465: return "SMTPS";
   case 587: return "SMTP Submission"; case 631: return "IPP"; case 636: return "LDAPS";
   case 993: return "IMAPS"; case 995: return "POP3S"; case 1433: return "Microsoft SQL Server";
   case 1521: return "Oracle DB"; case 1883: return "MQTT"; case 2049: return "NFS";
   case 2375: return "Docker API"; case 2376: return "Docker API TLS"; case 3306: return "MySQL / MariaDB";
   case 3389: return "RDP"; case 5432: return "PostgreSQL"; case 5900: return "VNC";
   case 5985: return "WinRM HTTP"; case 5986: return "WinRM HTTPS"; case 6379: return "Redis";
   case 8006: return "Proxmox HTTPS"; case 8080: return "HTTP alternativ"; case 8443: return "HTTPS alternativ";
   case 8883: return "MQTT TLS"; case 9100: return "Drucker JetDirect"; case 9200: return "Elasticsearch";
   case 11211: return "Memcached"; case 27017: return "MongoDB";
   default: return "Unbekannt / benutzerdefiniert";
  }
 }
 // Oeffnet fuer den ausgewaehlten Host eine manuelle oder vollstaendige TCP-Portsuche.
 static void OpenPortScan(bool manual) {
  var list=SortedHosts();
  if(list.Length==0) { dialogTitle="HINWEIS"; dialogMessage="Bitte zuerst einen Host in der Liste auswaehlen."; return; }
  portScan=new PortScanSession { Host=list[Math.Max(0,Math.Min(selected,list.Length-1))],Editing=manual,Input=manual?"":"1-65535" };
  if(!manual) RunPortScan(portScan,Enumerable.Range(1,65535).ToArray());
 }
 // Prueft die Portauswahl im Hintergrund mit begrenzter Parallelitaet und Zeitlimits.
 static void RunPortScan(PortScanSession session,int[] numbers) {
  if(session.Udp) { RunUdpScan(session,numbers); return; }
  session.Editing=false; session.Error=""; session.Total=numbers.Length; session.Running=true;
  session.Worker=Task.Run(async()=>{
   int next=-1;
   var token=session.Cancel.Token;
   try {
    var workers=Enumerable.Range(0,Math.Min(128,numbers.Length)).Select(async worker=>{
     while(!token.IsCancellationRequested) {
      int index=Interlocked.Increment(ref next);
      if(index>=numbers.Length) break;
      using(var client=new TcpClient()) {
       try {
        Task connect=client.ConnectAsync(session.Host.IP,numbers[index]);
        if(await Task.WhenAny(connect,Task.Delay(500,token))==connect) {
         await connect;
         if(client.Connected && !token.IsCancellationRequested) session.Open.TryAdd(numbers[index],true);
        } else Observe(connect);
       } catch(SocketException) {} catch(ObjectDisposedException) {} catch(OperationCanceledException) {}
       finally { Interlocked.Increment(ref session.Done); }
      }
     }
    }).ToArray();
    await Task.WhenAll(workers);
   } catch(Exception error) { session.Error=error.Message; }
   finally { session.Running=false; }
  });
 }
 static void OpenUdpScan() {
  OpenPortScan(true);
  if(portScan!=null) { portScan.Udp=true; portScan.Input="53,123,137,161,500,1900,4500,5353"; }
 }
 static byte[] UdpProbe(int port) {
  if(port==53 || port==5353) {
   byte[] query={0,0,1,0,0,1,0,0,0,0,0,0,0,0,2,0,1};
   byte[] id=Guid.NewGuid().ToByteArray(); query[0]=id[0]; query[1]=id[1]; return query;
  }
  if(port==123) { var packet=new byte[48]; packet[0]=0x23; return packet; }
  return new byte[0];
 }
 static async Task<string> ProbeUdp(string ip,int port,CancellationToken token) {
  using(var client=new UdpClient(AddressFamily.InterNetwork)) {
   try {
    token.ThrowIfCancellationRequested(); client.Connect(ip,port);
    byte[] packet=UdpProbe(port); await client.SendAsync(packet,packet.Length);
    Task<UdpReceiveResult> receive=client.ReceiveAsync();
    if(await Task.WhenAny(receive,Task.Delay(1000,token))!=receive) {
     client.Close(); Observe(receive); token.ThrowIfCancellationRequested(); return "open|filtered";
    }
    await receive; return "open";
   } catch(SocketException error) {
    if(error.SocketErrorCode==SocketError.ConnectionRefused || error.SocketErrorCode==SocketError.ConnectionReset) return "closed";
    return "filtered/error ("+error.SocketErrorCode+")";
   }
  }
 }
 static void RunUdpScan(PortScanSession session,int[] numbers) {
  session.Editing=false; session.Error=""; session.Total=numbers.Length; session.Running=true;
  session.Worker=Task.Run(async ()=> {
   int next=-1; var token=session.Cancel.Token;
   try {
    var workers=Enumerable.Range(0,Math.Min(16,numbers.Length)).Select(async worker=> {
     while(!token.IsCancellationRequested) {
      int index=Interlocked.Increment(ref next); if(index>=numbers.Length) break;
      try {
       string state=await ProbeUdp(session.Host.IP,numbers[index],token);
       if(!token.IsCancellationRequested) {
        session.UdpResults[numbers[index]]=state;
        if(state=="open") session.Open.TryAdd(numbers[index],true);
       }
      } finally { Interlocked.Increment(ref session.Done); }
     }
    }).ToArray();
    await Task.WhenAll(workers);
   } catch(OperationCanceledException) {} catch(Exception error) { session.Error=error.Message; }
   finally {
    session.Host.UdpPorts=string.Join("\n",session.UdpResults.OrderBy(pair=>pair.Key).Select(pair=>pair.Key+" / UDP: "+pair.Value));
    if(token.IsCancellationRequested) session.Host.UdpPorts+="\n"+ServiceText("Abgebrochen; Ergebnis unvollstaendig","Cancelled; partial results");
    session.Running=false;
   }
  });
 }
 // Bricht die aktuelle Portsuche ab und entfernt den Dialogzustand.
 static void ClosePortScan() {
  var session=portScan; if(session==null) return;
  session.Cancel.Cancel(); portScan=null;
 }
 // Bearbeitet Portauswahl, Start, Abbruch und Scrollposition des Portdialogs.
 static void HandlePortScanKey(ConsoleKeyInfo key) {
  var session=portScan;
  if(session==null) return;
  if(key.Key==ConsoleKey.Escape) { ClosePortScan(); return; }
  if(session.Editing) {
   if(key.Key==ConsoleKey.Enter) {
    try { RunPortScan(session,ParsePortSelection(session.Input)); } catch(ArgumentException error) { session.Error=error.Message; }
   } else if(key.Key==ConsoleKey.Backspace) { if(session.Input.Length>0) session.Input=session.Input.Substring(0,session.Input.Length-1); }
   else if(key.Key==ConsoleKey.A && (key.Modifiers & ConsoleModifiers.Control)!=0) session.Input="";
   else if(session.Input.Length<2000 && ((key.KeyChar>='0' && key.KeyChar<='9') || ",;- ".IndexOf(key.KeyChar)>=0)) session.Input+=key.KeyChar;
   return;
  }

  switch(key.Key) {

   case ConsoleKey.Enter: if(session.Running) session.Cancel.Cancel(); else ClosePortScan(); break;
   case ConsoleKey.UpArrow: session.Scroll=Math.Max(0,session.Scroll-1); break;
   case ConsoleKey.DownArrow: session.Scroll++; break;
   case ConsoleKey.PageUp: session.Scroll=Math.Max(0,session.Scroll-Math.Max(1,Math.Min(24,Console.WindowHeight-2)-9)); break;
   case ConsoleKey.PageDown: session.Scroll+=Math.Max(1,Math.Min(24,Console.WindowHeight-2)-9); break;
   case ConsoleKey.Home: session.Scroll=0; break;
   case ConsoleKey.End: session.Scroll=session.Udp?session.UdpResults.Count:session.Open.Count; break;
  }
 }
 // Zeichnet Portfortschritt und numerisch sortierte Treffer mit Diensthinweisen.
 static void DrawPortScan(int width,int height) {
  var session=portScan; if(session==null) return;
  int boxWidth=Math.Min(90,width-4),boxHeight=Math.Min(24,height-2),inner=boxWidth-2;
  int x=(width-boxWidth)/2,y=(height-boxHeight)/2,resultRows=boxHeight-9;
  var open=(session.Udp?session.UdpResults.Keys:session.Open.Keys).OrderBy(number=>number).ToArray();
  session.Scroll=Math.Max(0,Math.Min(session.Scroll,Math.Max(0,open.Length-resultRows)));
  string state=session.Editing?T("Ports eingeben (Komma, Leerzeichen oder Bereich mit -)"):session.Running?T("Scan laeuft"):session.Cancel.IsCancellationRequested?T("Abgebrochen"):T("Scan abgeschlossen");
  var lines=new System.Collections.Generic.List<string>();
  lines.Add("\u250c"+new string('\u2500',inner)+"\u2510");
  lines.Add("\u2502"+Cell(session.Udp?" UDP-Portscan":T(" TCP-Portscan"),inner)+"\u2502");
  lines.Add("\u2502"+Cell(" Host: "+session.Host.IP+"  "+DisplayHostName(session.Host),inner)+"\u2502");
  string input=session.Input;
  if(session.Editing && input.Length>inner-10) input=input.Substring(input.Length-(inner-10));
  lines.Add("\u2502"+Cell(" Ports: "+input+(session.Editing?"_":""),inner)+"\u2502");
  lines.Add("\u2502"+Cell(" "+(session.Error.Length>0?TranslateMessage(session.Error):state+(session.Editing?"":" | "+session.Done+"/"+session.Total+T(" | Offen: ")+session.Open.Count)),inner)+"\u2502");
  lines.Add("\u2502"+Cell(session.Udp?ServiceText(" open: Antwort | closed: ICMP | open|filtered: keine Antwort"," open: reply | closed: ICMP | open|filtered: no reply"):T(" Dienstnamen nach Portnummer; tatsaechlicher Dienst kann abweichen."),inner)+"\u2502");
  lines.Add("\u251c"+new string('\u2500',inner)+"\u2524");
  for(int row=0;row<resultRows;row++) {
   int index=session.Scroll+row;
   string value=index<open.Length?" "+open[index].ToString().PadRight(5)+(session.Udp?" / UDP   "+session.UdpResults[open[index]]:" / TCP   "+T(PortService(open[index]))):row==0 && !session.Editing && open.Length==0?T(" Noch keine offenen Ports gefunden."):"";
   lines.Add("\u2502"+Cell(value,inner)+"\u2502");
  }
  lines.Add("\u2502"+Cell(session.Editing?T(" Enter: Start | Ctrl+A: Leeren | Esc: Schliessen"):session.Running?T(" Enter: Abbrechen | Pfeile/Bild auf/ab: Scrollen | Esc: Schliessen"):T(" Enter/Esc: Schliessen | Pfeile/Bild auf/ab: Scrollen"),inner)+"\u2502");
  lines.Add("\u2514"+new string('\u2500',inner)+"\u2518");
  bool full=session.Rendered==null || session.X!=x || session.Y!=y || session.Rendered.Length!=lines.Count || session.Rendered[0].Length!=boxWidth;
  var foreground=ThemeForeground; var background=ThemeBackground;
  try {
   ThemeForeground=ConsoleColor.White; ThemeBackground=ConsoleColor.DarkBlue;
   for(int row=0;row<lines.Count;row++) {
    if(!full && session.Rendered[row]==lines[row]) continue;
    Console.SetCursorPosition(x,y+row); if(row==1) WritePopupHeading(lines[row]); else Console.Write(lines[row]);
   }
  } finally { ThemeForeground=foreground; ThemeBackground=background; }
  session.Rendered=lines.ToArray(); session.X=x; session.Y=y;
 }
 sealed class PingSession {
  public string Address,Name;
  public readonly object Sync=new object();
  public CancellationTokenSource Cancel=new CancellationTokenSource();
  public readonly System.Collections.Generic.Queue<string> History=new System.Collections.Generic.Queue<string>();
  public Task Worker;
  public int Sent,Received;
  public long Sum,Minimum=long.MaxValue,Maximum;
  public bool Running=true,ResumeRequested;
 }
 static PingSession continuousPing;
 static string[] renderedPingLines;
 static int renderedPingX,renderedPingY;
 // Oeffnet fuer den ausgewaehlten Host eine neue Dauerping-Sitzung.
 static void StartContinuousPing() {
  var list=SortedHosts();
  if(list.Length==0) { dialogTitle="FEHLER"; dialogMessage="Kein Host fuer Dauerping ausgewaehlt."; return; }
  var host=list[Math.Max(0,Math.Min(selected,list.Length-1))];
  var session=new PingSession { Address=host.IP,Name=host.DNS };
  continuousPing=session; renderedPingLines=null;
  RunContinuousPing(session);
 }
 // Sammelt Pingantworten und Statistik im Hintergrund mit begrenzter Historie.
 static void RunContinuousPing(PingSession session) {
  var token=session.Cancel.Token;
  session.Running=true;
  session.Worker=Task.Run(async()=>{
   try {
    using(var ping=new Ping()) {
     while(!token.IsCancellationRequested) {
      string result; long latency=-1;
      try {
       var reply=await ping.SendPingAsync(session.Address,1000);
       if(reply.Status==IPStatus.Success) { latency=reply.RoundtripTime; result="Antwort: "+FormatPing(latency); }
       else result=reply.Status==IPStatus.TimedOut?"Zeitueberschreitung":reply.Status.ToString();
      } catch(PingException) { result="Ping fehlgeschlagen"; }
      if(token.IsCancellationRequested) break;
      lock(session.Sync) {
       session.Sent++;
       if(latency>=0) { session.Received++; session.Sum+=latency; session.Minimum=Math.Min(session.Minimum,latency); session.Maximum=Math.Max(session.Maximum,latency); }
       session.History.Enqueue(DateTime.Now.ToString("HH:mm:ss")+"  "+result);
       while(session.History.Count>100) session.History.Dequeue();
      }
      await Task.Delay(600,token);
     }
    }
   } catch(OperationCanceledException) {}
   finally { lock(session.Sync) session.Running=false; }
  });
 }
 // Pausiert den Dauerping oder merkt die Wiederaufnahme nach dem laufenden Worker vor.
 static void ToggleContinuousPing() {
  var session=continuousPing;
  if(session==null) return;
  if(!session.Cancel.IsCancellationRequested) { StopContinuousPing(false); return; }
  session.ResumeRequested=!session.ResumeRequested;
  ResumeContinuousPingIfReady();
 }
 // Startet eine vorgemerkte Wiederaufnahme erst nach Abschluss des alten Workers.
 static void ResumeContinuousPingIfReady() {
  var session=continuousPing;
  if(session==null || !session.ResumeRequested || (session.Worker!=null && !session.Worker.IsCompleted)) return;
  session.ResumeRequested=false;
  session.Cancel.Dispose(); session.Cancel=new CancellationTokenSource(); RunContinuousPing(session);
 }
 // Bricht den Dauerping ab und schliesst bei Bedarf auch das Popup.
 static void StopContinuousPing(bool close) {
  var session=continuousPing;
  if(session!=null) { session.ResumeRequested=false; session.Cancel.Cancel(); }
  if(close) { continuousPing=null; renderedPingLines=null; }
 }
 // Zeichnet Dauerping und Statistik und schreibt nur geaenderte Popup-Zeilen.
 static void DrawContinuousPing(int width,int height) {
  var session=continuousPing;
  if(session==null) return;
  int boxWidth=Math.Min(76,width-4),boxHeight=Math.Min(20,height-2);
  int x=(width-boxWidth)/2,y=(height-boxHeight)/2,inner=boxWidth-2;
  var lines=new System.Collections.Generic.List<string>();
  string border="\u250c"+new string('\u2500',inner)+"\u2510";
  string bottom="\u2514"+new string('\u2500',inner)+"\u2518";
  lines.Add(border);
  lines.Add("\u2502"+Cell(T(" Dauerping: ")+session.Address,inner)+"\u2502");
  lines.Add("\u2502"+Cell(" "+DisplayStatus(session.Name),inner)+"\u2502");
  lock(session.Sync) {
   int lost=session.Sent-session.Received;
   lines.Add("\u2502"+Cell(T(" Gesendet: ")+session.Sent+T(" \u2502 Antworten: ")+session.Received+T(" \u2502 Verlust: ")+lost+" ("+(session.Sent==0?0:lost*100/session.Sent)+"%)",inner)+"\u2502");
   string timing=session.Received==0?T(" Noch keine Antwort"):" Min/Avg/Max: "+FormatPing(session.Minimum)+" / "+FormatPing(session.Sum/session.Received)+" / "+FormatPing(session.Maximum);
   lines.Add("\u2502"+Cell(timing,inner)+"\u2502");
   lines.Add("\u251c"+new string('\u2500',inner)+"\u2524");
   int historyRows=boxHeight-8;
   var history=session.History.Skip(Math.Max(0,session.History.Count-historyRows)).ToArray();
   for(int i=0;i<historyRows;i++) lines.Add("\u2502"+Cell(i<history.Length?" "+TranslatePingHistory(history[i]):"",inner)+"\u2502");
   lines.Add("\u2502"+Cell(session.Running?T(" F4: Stoppen \u2502 Enter/Esc: Schliessen"):T(" Gestoppt \u2502 F4: Fortsetzen \u2502 Enter/Esc: Schliessen"),inner)+"\u2502");
  }
  lines.Add(bottom);
  bool full=renderedPingLines==null || renderedPingX!=x || renderedPingY!=y || renderedPingLines.Length!=lines.Count || renderedPingLines[0].Length!=boxWidth;
  ConsoleColor foreground=ThemeForeground,background=ThemeBackground;
  try {
   ThemeForeground=ConsoleColor.White; ThemeBackground=ConsoleColor.DarkBlue;
   for(int row=0;row<lines.Count;row++) {
    if(!full && lines[row]==renderedPingLines[row]) continue;
    Console.SetCursorPosition(x,y+row); if(row==1) WritePopupHeading(lines[row]); else Console.Write(lines[row]);
   }
  } finally { ThemeForeground=foreground; ThemeBackground=background; }
  renderedPingLines=lines.ToArray(); renderedPingX=x; renderedPingY=y;
 }
 // Stellt die lokalisierten Bedienhinweise fuer den Hilfedialog zusammen.
 static void ShowHelp() {
  dialogTitle="Kubscan - Info";
  var common=new[]{
   "F1          Funktionsuebersicht anzeigen",
   "T           Theme auswaehlen",
   "L           Sprache wechseln (Deutsch / Englisch)",
   "A           ARP-Listenmodus / IP-Scan umschalten",
   "M           mDNS-Dienste / IP-Scan umschalten",
   "F10         Anwendung beenden"
  };
  var mode=listenMode?new[]{
   English?"F2          Start / resume capture":"F2          Mitschnitt starten / fortsetzen",
   English?"F3          Start new capture":"F3          Neuen Mitschnitt starten",
   English?"F4          Select network adapter":"F4          Netzwerkadapter auswaehlen",
   English?"F7          Search ARP entries":"F7          ARP-Eintraege durchsuchen",
   English?"F9 / Esc    Stop capture (Esc clears search first)":"F9 / Esc    Mitschnitt stoppen (Esc leert zuerst die Suche)",
   English?"Up/Down     Scroll capture":"Hoch/Runter Mitschnitt scrollen",
   English?"PgUp/PgDn   Scroll by page":"Bild hoch/runter Seitenweise scrollen",
   English?"Home/End    First / latest entries":"Pos1/Ende   Erste / neueste Eintraege"
  }:mdnsMode?new[]{
   English?"F2          Rescan":"F2          Rescan",
   English?"F7          Search mDNS services":"F7          mDNS-Dienste durchsuchen",
   English?"F9 / Esc    Cancel discovery (Esc clears search first)":"F9 / Esc    Suche abbrechen (Esc leert zuerst den Filter)",
   English?"Space/Enter Open service / host details":"Leertaste/Enter Dienst / Hostdetails oeffnen",
   "C           Aktuellen Spaltenwert kopieren",
   "Hoch/Runter Host in der Liste auswaehlen",
   English?"PgUp/PgDn   Select by page":"Bild hoch/runter Seitenweise auswaehlen",
   English?"Home/End    First / last entry":"Pos1/Ende   Erster / letzter Eintrag",
   "Links/Rechts Sortierspalte waehlen (Ueberschrift blau)"
  }:new[]{
   "S           Alle TCP-Ports des markierten Hosts pruefen",
   "P           TCP-Ports fuer markierten Host eingeben",
   English?"U           Scan UDP ports of selected host":"U           UDP-Ports des markierten Hosts pruefen",
   "O           Betriebssystem des markierten Hosts abschaetzen",
   "F2 / Enter  Scan starten",
   "Scanbereich CIDR oder Start-IP bis End-IP mit -",
   "Leertaste   Hostdetails des ausgewaehlten Hosts",
   English?"            Arrows / PgUp / PgDn: scroll details":"            Pfeile / Bild auf/ab: Details scrollen",
   "Esc         Hostdetails schliessen",
   English?"F3          Continuous scan / stop":"F3          Continuous-Scan starten / stoppen",
   "C           Aktuellen Spaltenwert kopieren",
   "F4          Dauerping starten / stoppen / fortsetzen",
   "F5          Ergebnisse als CSV exportieren",
   "F6          Ergebnisse als Plaintext exportieren",
   "F7          Suche in IP, DNS, MAC und Hersteller",
   "            Enter: Uebernehmen, Esc: Suche loeschen",
   "F8          IEEE-OUI-Datenbank aktualisieren",
   "F9 / Esc    Laufenden Scan abbrechen",
   "Hoch/Runter Host in der Liste auswaehlen",
   "Links/Rechts Sortierspalte waehlen (Ueberschrift blau)"
  };
  dialogMessage=string.Join("\n",common.Concat(mode));
 }
 static string cidrInput;
 static int cidrIndex=8;
 // Berechnet Netzmaske, Hostzahl und nutzbaren Bereich einer CIDR-Menueoption.
 static string CidrOption(int index) { return FormatCidrOption(cidrInput,index); }
 static string FormatCidrOption(string input,int index) {
  int prefix=32-index;
  uint mask=uint.MaxValue << (32-prefix),address=ParseIPv4(input);
  uint network=address&mask;
  uint size=1U << (32-prefix),skip=prefix<31?1U:0U;
  uint count=size-2*skip,first=network+skip,last=network+size-skip-1;
  return ("/"+prefix+" ("+IP(mask)+")").PadRight(21)+" | "+(count+" Hosts").PadRight(11)+" | "+IP(first)+" - "+IP(last);
 }
 // Bearbeitet die CIDR-Auswahl und startet bei Bestaetigung den gewaehlten Bereich.
 static string HandleCidr(ConsoleKey key,string input) {
  switch(key) {
   case ConsoleKey.UpArrow: cidrIndex=Math.Max(0,cidrIndex-1); break;
   case ConsoleKey.DownArrow: cidrIndex=Math.Min(16,cidrIndex+1); break;
   case ConsoleKey.Home: cidrIndex=0; break;
   case ConsoleKey.End: cidrIndex=16; break;
   case ConsoleKey.PageUp: cidrIndex=Math.Max(0,cidrIndex-5); break;
   case ConsoleKey.PageDown: cidrIndex=Math.Min(16,cidrIndex+5); break;
   case ConsoleKey.Escape: cidrInput=null; break;
   case ConsoleKey.Enter:
    input=cidrInput+"/"+(32-cidrIndex);
    cidrInput=null;
    Start(input);
    break;
  }
  return input;
 }
 // Zeichnet die CIDR-Auswahlliste mit markierter Praefixlaenge.
 static void DrawCidr(int width,int height) {
  if(cidrInput==null) return;
  int visible=Math.Min(17,height-6),boxWidth=Math.Min(84,width-4),boxHeight=visible+6;
  int x=(width-boxWidth)/2,y=(height-boxHeight)/2;
  int first=Math.Max(0,Math.Min(cidrIndex-visible/2,17-visible));
  string border="\u250c"+new string('\u2500',boxWidth-2)+"\u2510";
  string bottom="\u2514"+new string('\u2500',boxWidth-2)+"\u2518";
  ConsoleColor foreground=ThemeForeground,background=ThemeBackground;
  try {
   ThemeForeground=ConsoleColor.White; ThemeBackground=ConsoleColor.DarkBlue;
   Console.SetCursorPosition(x,y); Console.Write(border);
   Console.SetCursorPosition(x,y+1); WritePopupHeading("\u2502"+Cell(T(" CIDR auswaehlen: ")+cidrInput,boxWidth-2)+"\u2502");
   Console.SetCursorPosition(x,y+2); Console.Write("\u2502"+new string(' ',boxWidth-2)+"\u2502");
   for(int row=0;row<visible;row++) {
    Console.SetCursorPosition(x,y+3+row); Console.Write("\u2502");
    bool active=first+row==cidrIndex;
    ThemeForeground=active?ConsoleColor.DarkBlue:ConsoleColor.White;
    ThemeBackground=active?ConsoleColor.White:ConsoleColor.DarkBlue;
    Console.Write(Cell(" "+CidrOption(first+row),boxWidth-2));
    ThemeForeground=ConsoleColor.White; ThemeBackground=ConsoleColor.DarkBlue; Console.Write("\u2502");
   }
   Console.SetCursorPosition(x,y+visible+3); Console.Write("\u2502"+new string(' ',boxWidth-2)+"\u2502");
   Console.SetCursorPosition(x,y+visible+4); Console.Write("\u2502"+Cell(T(" Hoch/Runter: Auswahl \u2502 Enter: Scan \u2502 Esc: Zurueck"),boxWidth-2)+"\u2502");
   Console.SetCursorPosition(x,y+visible+5); Console.Write(bottom);
  } finally { ThemeForeground=foreground; ThemeBackground=background; }
 }
 // Zeichnet Download- und Installationsfortschritt der Herstellerdatenbank.
 static void DrawOuiPopup(int width,int height) {
  if(!ouiPopup) return;
  int progress=ouiProgress;
  string phase=ouiPhase;
  long received=Interlocked.Read(ref ouiReceived),length=Interlocked.Read(ref ouiLength);
  bool busy=ouiUpdate!=null && !ouiUpdate.IsCompleted;
  int animation=(Environment.TickCount & int.MaxValue)/120;
  string key=progress+"\u2502"+phase+"\u2502"+received+"\u2502"+length+"\u2502"+busy+"\u2502"+width+"\u2502"+height+(progress==-1?"\u2502"+animation:"");
  if(key==renderedOuiProgress) return;
  int boxWidth=Math.Min(70,width-4),x=(width-boxWidth)/2,y=(height-10)/2;
  int inner=boxWidth-2,barWidth=inner-9;
  string border="\u250c"+new string('\u2500',inner)+"\u2510";
  string bottom="\u2514"+new string('\u2500',inner)+"\u2518";
  string transfer=(received/1024)+" KiB"+(length>0?" / "+(length/1024)+" KiB":"");
  string footer=busy?T("Aktualisierung laeuft ..."):T("Enter / Esc: Schliessen");
  string[] lines={border,"\u2502"+Cell(T(" OUI-Datenbank aktualisieren"),inner)+"\u2502","\u2502"+new string(' ',inner)+"\u2502","\u2502"+Cell(" "+TranslateMessage(phase),inner)+"\u2502","\u2502"+Cell(" "+transfer,inner)+"\u2502","\u2502"+new string(' ',inner)+"\u2502","\u2502"+new string(' ',inner)+"\u2502","\u2502"+Cell(busy?"":" "+TranslateMessage(exportMessage),inner)+"\u2502","\u2502"+Cell(" "+footer,inner)+"\u2502",bottom};
  var colors=lines.Select(line=>Enumerable.Repeat(ConsoleColor.DarkBlue,line.Length).ToArray()).ToArray();
  int filled=progress>=0?ProgressValue(progress,100,barWidth):0,start=0;
  if(progress==-1) { filled=Math.Min(5,barWidth); start=animation%Math.Max(1,barWidth-filled+1); }
  for(int i=0;i<barWidth;i++) colors[5][2+i]=ConsoleColor.Black;
  for(int i=0;i<filled;i++) colors[5][2+start+i]=i==filled-1?ConsoleColor.White:MenuBackground;
  char[] bar=lines[5].ToCharArray();
  string percent=Cell(progress>=0?progress+"%":progress==-1?"...":T("Fehler"),6);
  for(int i=0;i<percent.Length;i++) bar[2+barWidth+1+i]=percent[i];
  lines[5]=new string(bar);
  bool full=renderedOuiProgress==null || renderedOuiLines==null || renderedOuiX!=x || renderedOuiY!=y || renderedOuiLines[0].Length!=boxWidth;
  ConsoleColor foreground=ThemeForeground,background=ThemeBackground;
  try {
   ThemeForeground=ConsoleColor.White;
   for(int row=0;row<lines.Length;row++) {
    if(row==1) {
     if(full || lines[row]!=renderedOuiLines[row]) { ThemeBackground=ConsoleColor.DarkBlue; Console.SetCursorPosition(x,y+row); WritePopupHeading(lines[row]); }
     continue;
    }
    int column=0;
    while(column<lines[row].Length) {
     if(!full && lines[row][column]==renderedOuiLines[row][column] && colors[row][column]==renderedOuiColors[row][column]) { column++; continue; }
     int from=column;
     ConsoleColor color=colors[row][column];
     column++;
     while(column<lines[row].Length && colors[row][column]==color && (full || lines[row][column]!=renderedOuiLines[row][column] || colors[row][column]!=renderedOuiColors[row][column])) column++;
     Console.SetCursorPosition(x+from,y+row);
     ThemeBackground=color;
     Console.Write(lines[row].Substring(from,column-from));
    }
   }
  } finally { ThemeForeground=foreground; ThemeBackground=background; }
  renderedOuiLines=lines; renderedOuiColors=colors; renderedOuiX=x; renderedOuiY=y;
  renderedOuiProgress=key;
 }
 // Zeichnet allgemeine Hilfe- und Fehlermeldungen als zentriertes Popup.
 static void DrawThemePicker(int width,int height) {
  string hint=English?"Preview: arrows; Enter: save; Escape: back":"Vorschau: Pfeile; Enter: speichern; Escape: zurueck";
  int boxWidth=Math.Min(width-4,Math.Max(54,hint.Length+4)),boxHeight=themes.Length+5;
  if(boxWidth<4 || height<boxHeight) return;
  int inner=boxWidth-2,x=(width-boxWidth)/2,y=(height-boxHeight)/2;
  ConsoleColor foreground=ThemeForeground,background=ThemeBackground;
  try {
   ThemeBackground=ConsoleColor.DarkBlue; ThemeForeground=HeadingColor;
   Console.SetCursorPosition(x,y); Console.Write("\u250c"+" Themes".PadRight(inner,'\u2500').Substring(0,inner)+"\u2510");
   Console.SetCursorPosition(x,y+1); Console.Write("\u2502"+Cell(" "+hint,inner)+"\u2502");
   Console.SetCursorPosition(x,y+2); Console.Write("\u251c"+new string('\u2500',inner)+"\u2524");
   for(int i=0;i<themes.Length;i++) {
    Console.SetCursorPosition(x,y+3+i);
    ThemeBackground=ConsoleColor.DarkBlue; ThemeForeground=HeadingColor; Console.Write("\u2502");
    if(i==themeSelection) {
     ThemeBackground=ConsoleColor.DarkGray; ThemeForeground=ConsoleColor.White;
     if(themeIndex>0 && trueColorEnabled) Console.Write(RgbSequence(BlendColor(themes[themeIndex].Accent,themes[themeIndex].Panel,35),true));
    }
    string name=themes[i].Name=="Rose Pine"?"Ros\u00e9 Pine":themes[i].Name;
    Console.Write(Cell(" "+name+(i==themeSelection?(English?" [selected]":" [ausgewaehlt]"):""),inner));
    ThemeBackground=ConsoleColor.DarkBlue; ThemeForeground=HeadingColor; Console.Write("\u2502");
   }
   Console.SetCursorPosition(x,y+3+themes.Length); Console.Write("\u2502"+new string(' ',inner)+"\u2502");
   Console.SetCursorPosition(x,y+4+themes.Length); Console.Write("\u2514"+new string('\u2500',inner)+"\u2518");
  } finally { ThemeForeground=foreground; ThemeBackground=background; }
 }
 static void DrawDialog(int width,int height) {
  if(themePicker) { DrawThemePicker(width,height); return; }
  if(dialogMessage==null) return;
  string[] body=dialogMessage.Split('\n').Select(TranslateMessage).ToArray();
  int boxWidth=Math.Min(width-4,Math.Max(themePicker?58:48,body.Max(line=>line.Length)+6)),boxHeight=body.Length+6;
  int x=(width-boxWidth)/2,y=(height-boxHeight)/2;
  string border="\u250c"+new string('\u2500',boxWidth-2)+"\u2510";
  string bottom="\u2514"+new string('\u2500',boxWidth-2)+"\u2518";
  var lines=new System.Collections.Generic.List<string>();
  lines.Add(border); lines.Add("\u2502"+Cell(" "+T(dialogTitle),boxWidth-2)+"\u2502"); lines.Add("\u2502"+new string(' ',boxWidth-2)+"\u2502");
  foreach(string line in body) lines.Add("\u2502"+Cell(" "+line,boxWidth-2)+"\u2502");
  lines.Add("\u2502"+new string(' ',boxWidth-2)+"\u2502");
  string footer=themePicker?(English?" Up/Down: Select | Enter: Apply | Esc: Cancel":" Hoch/Runter: Auswahl | Enter: OK | Esc: Abbruch"):" [ OK ]  Enter / Esc";
  lines.Add("\u2502"+Cell(footer,boxWidth-2)+"\u2502"); lines.Add(bottom);
  ConsoleColor foreground=ThemeForeground,background=ThemeBackground;
  try {
   ThemeForeground=ConsoleColor.White;
   ThemeBackground=dialogTitle=="FEHLER"?ConsoleColor.DarkRed:ConsoleColor.DarkBlue;
   for(int i=0;i<lines.Count;i++) { Console.SetCursorPosition(x,y+i); if(i==1) WritePopupHeading(lines[i]); else Console.Write(lines[i]); }
  } finally { ThemeForeground=foreground; ThemeBackground=background; }
 }
 static int maskScroll=0;
 static readonly string[] subnetMasks=Enumerable.Range(16,17).Reverse()
  .Select(prefix=>"/"+prefix.ToString().PadRight(4)+IP(uint.MaxValue << (32-prefix))).ToArray();
 // Liefert die einmalig berechnete, intern nur lesend verwendete /32-bis-/16-Referenz.
 static string[] SubnetMasks() { return subnetMasks; }
 static string renderedModal;
 static int renderedWidth,renderedHeight,renderedCidrIndex;
 // Aktualisiert nur den aktiven Dialog, solange sein Hintergrund und Layout gleich bleiben.
 static bool ReuseModalFrame(string modal,int width,int height) {
  if(modal==null || modal!=renderedModal || width!=renderedWidth || height!=renderedHeight) return false;
  if(modal=="OUI") DrawOuiPopup(width,height);
  if(modal=="PING") DrawContinuousPing(width,height);
  if(modal=="PORTSCAN") DrawPortScan(width,height);
  if(modal=="EXPORT") DrawExportDialog(width,height);
  if(cidrInput!=null && cidrIndex!=renderedCidrIndex) {
   DrawCidr(width,height);
   renderedCidrIndex=cidrIndex;
  }
  return true;
 }
 static string renderedIdleFrame;
 // Beschreibt den sichtbaren Startbildschirmzustand zur Vermeidung identischer Frames.
 static string IdleFrameKey(string input,int width,int height) {
  return string.Join("\u001f",new[]{input??"",width.ToString(),height.ToString(),maskScroll.ToString(),message,exportMessage,searchText,searchEditing.ToString()});
 }
 sealed class DetailLine {
  public string Text; public bool IsLabel;
  // Kennzeichnet Beschriftungen getrennt von Werten fuer Farbe und Zeilenumbruch.
  public DetailLine(string text,bool isLabel=false) { Text=text; IsLabel=isLabel; }
 }
 // Trennt Beschriftung und Wert, bereinigt Steuerzeichen und bricht den Wert passend um.
 static void AddDetail(System.Collections.Generic.List<DetailLine> lines,string label,string value,int width) {
  lines.Add(new DetailLine(T(label)+":",true));
  string clean=ExportTextValue(value);
  int available=Math.Max(1,width);
  if(clean.Length==0) { lines.Add(new DetailLine("")); lines.Add(new DetailLine("")); return; }
  for(int pos=0;pos<clean.Length;pos+=available) {
   lines.Add(new DetailLine(clean.Substring(pos,Math.Min(available,clean.Length-pos))));
  }
  lines.Add(new DetailLine(""));
 }
 // Formatiert Pingzeiten inklusive Antworten unter einer Millisekunde.
 static string FormatPing(long milliseconds) { return milliseconds<=0?"<0ms":milliseconds.ToString(System.Globalization.CultureInfo.InvariantCulture)+" ms"; }
 // Erzeugt lokalisierte Hostdetails mit getrennten Beschriftungs- und Wertezeilen.
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]
 struct ShareInfo { public string Name; public uint Type; public string Remark; }
 [DllImport("Netapi32.dll",CharSet=CharSet.Unicode)]
 static extern int NetShareEnum(string server,int level,out IntPtr buffer,int length,out int read,out int total,ref int resume);
 [DllImport("Netapi32.dll")] static extern int NetApiBufferFree(IntPtr buffer);
 static readonly SemaphoreSlim shareProbeSlots=new SemaphoreSlim(2);
 static readonly SemaphoreSlim webProbeSlots=new SemaphoreSlim(4);
 static string ServiceText(string de,string en) { return English?en:de; }
 static string ReadShares(string ip,Action<string> discovered=null) {
  if(!IsWindows) {
   try {
    var info=new System.Diagnostics.ProcessStartInfo("smbclient","-g -L "+ip+" -N -t 4");
    info.UseShellExecute=false; info.CreateNoWindow=true; info.RedirectStandardOutput=true; info.RedirectStandardError=true;
    using(var process=System.Diagnostics.Process.Start(info)) {
     var output=process.StandardOutput.ReadToEndAsync(); var error=process.StandardError.ReadToEndAsync();
     if(!process.WaitForExit(6000)) { process.Kill(); return ServiceText("Zeitueberschreitung","Timed out"); }
     string[] shares=output.GetAwaiter().GetResult().Split('\n').Where(line=>line.StartsWith("Disk|",StringComparison.Ordinal)).Select(line=>line.TrimEnd('\r').Substring(5).Replace("|"," - ")).ToArray();
     if(shares.Length>0) return string.Join("\n",shares);
     return process.ExitCode==0?ServiceText("Keine Dateifreigaben gemeldet","No file shares reported"):ServiceText("Freigaben nicht abrufbar (Zugriff verweigert oder SMB-Fehler)","Cannot enumerate shares (access denied or SMB error)");
    }
   } catch(System.ComponentModel.Win32Exception) { return ServiceText("Zur Freigabenabfrage wird smbclient benoetigt","Share enumeration requires smbclient"); }
  }
  var result=new System.Collections.Generic.List<string>(); int resume=0,status;
  do {
   IntPtr buffer=IntPtr.Zero; int read,total;
   try {
    status=NetShareEnum("\\\\"+ip,1,out buffer,65536,out read,out total,ref resume);
    if(status!=0 && status!=234) return ServiceText("Freigaben nicht abrufbar; Windows-Fehler ","Cannot enumerate shares; Windows error ")+status;
    int size=Marshal.SizeOf(typeof(ShareInfo));
    for(int i=0;i<read;i++) {
     var share=(ShareInfo)Marshal.PtrToStructure(IntPtr.Add(buffer,i*size),typeof(ShareInfo));
     if((share.Type&0xffff)==0) {
      string path="\\\\"+ip+"\\"+share.Name;
      if(discovered!=null) discovered(path);
      result.Add(path+(string.IsNullOrEmpty(share.Remark)?"":" - "+ExportTextValue(share.Remark)));
     }
    }
   } finally { if(buffer!=IntPtr.Zero) NetApiBufferFree(buffer); }
  } while(status==234);
  return result.Count==0?ServiceText("Keine Dateifreigaben gemeldet","No file shares reported"):string.Join("\n",result);
 }
 static string ReadWebServer(string ip,int port) {
  bool tls=port==443 || port==8443 || port==8006;
  string url=(tls?"https":"http")+"://"+ip+":"+port+"/";
  return ReadWebHeader(url);
 }
 static string ReadWebHeader(string url) {
  return ReadWebHeaderFallback(url,null);
 }
 sealed class WebHeaderResult {
  public string Server,Error;
  public bool Responded;
  public int Status;
 }
 static WebHeaderResult RequestWebHeader(string url,string method,string hostname,bool tls12=false) {
  if(tls12) return RequestTls12Header(url,hostname);
  var request=(HttpWebRequest)WebRequest.Create(url);
  if(request.RequestUri.Scheme=="https") request.ServerCertificateValidationCallback=(sender,certificate,chain,errors)=>true;
  if(!string.IsNullOrEmpty(hostname)) request.Host=hostname+(request.RequestUri.IsDefaultPort?"":":"+request.RequestUri.Port);
  request.Method=method; request.Timeout=8000; request.ReadWriteTimeout=8000; request.AllowAutoRedirect=false; request.Proxy=null;
  request.UserAgent="KubScan/"+Version;
  HttpWebResponse response=null;
  try {
   try { response=(HttpWebResponse)request.GetResponse(); }
   catch(WebException error) {
    response=error.Response as HttpWebResponse;
    if(response==null) {
     string category=error.Status==WebExceptionStatus.Timeout?ServiceText("Zeitueberschreitung","Timeout"):
      error.Status==WebExceptionStatus.TrustFailure || error.Status==WebExceptionStatus.SecureChannelFailure?"TLS-Handshake":
      error.Status==WebExceptionStatus.NameResolutionFailure?"DNS":ServiceText("Verbindung","Connection");
     for(Exception cause=error.InnerException;cause!=null;cause=cause.InnerException) {
      if(cause is System.Security.Authentication.AuthenticationException) category="TLS-Handshake";
      if(cause is TimeoutException) category=ServiceText("Zeitueberschreitung","Timeout");
     }
     return new WebHeaderResult { Error=category+" ("+error.Status+"): "+error.GetBaseException().Message };
    }
   }
   return new WebHeaderResult { Server=response.Headers["Server"],Responded=true,Status=(int)response.StatusCode };
  } finally { if(response!=null) response.Close(); request.Abort(); }
 }
 static WebHeaderResult RequestTls12Header(string url,string hostname,string method="HEAD",bool http10=false) {
  var uri=new Uri(url);
  using(var client=new TcpClient()) {
   try {
    Task connect=client.ConnectAsync(uri.Host,uri.Port);
    if(!connect.Wait(8000)) { Observe(connect); return new WebHeaderResult { Error="TLS 1.2: Timeout (connect)" }; }
    using(var tls=new System.Net.Security.SslStream(client.GetStream(),false,(sender,certificate,chain,errors)=>true)) {
     tls.ReadTimeout=8000; tls.WriteTimeout=8000;
     Task handshake=tls.AuthenticateAsClientAsync(hostname??uri.Host,null,System.Security.Authentication.SslProtocols.Tls12,false);
     if(!handshake.Wait(8000)) { Observe(handshake); return new WebHeaderResult { Error="TLS 1.2: Timeout (handshake)" }; }
     string host=hostname??uri.Host;
     byte[] query=System.Text.Encoding.ASCII.GetBytes(method+" "+uri.PathAndQuery+(http10?" HTTP/1.0":" HTTP/1.1")+"\r\nHost: "+host+(uri.IsDefaultPort?"":":"+uri.Port)+"\r\nUser-Agent: Mozilla/5.0 KubScan/"+Version+"\r\nAccept: */*\r\nConnection: close\r\n\r\n");
     tls.Write(query,0,query.Length);
     var header=new byte[16384]; int length=0,headerEnd=-1;
     var clock=System.Diagnostics.Stopwatch.StartNew();
     while(length<header.Length && clock.ElapsedMilliseconds<8000 && headerEnd<0) {
      tls.ReadTimeout=Math.Max(1,8000-(int)clock.ElapsedMilliseconds);
      int read=tls.Read(header,length,Math.Min(4096,header.Length-length));
      if(read==0) break;
      int nextLength=length+read;
      for(int index=length;index<nextLength;index++) {
       if((index>=1 && header[index-1]==10 && header[index]==10) ||
          (index>=3 && header[index-3]==13 && header[index-2]==10 && header[index-1]==13 && header[index]==10)) {
        headerEnd=index+1; break;
       }
      }
      length=nextLength;
     }
     string[] lines=System.Text.Encoding.GetEncoding(28591).GetString(header,0,headerEnd>=0?headerEnd:length).Replace("\r\n","\n").Split('\n');
     int status; string[] first=lines[0].Split(' ');
     if(first.Length<2 || !first[0].StartsWith("HTTP/",StringComparison.Ordinal) || !int.TryParse(first[1],out status)) return new WebHeaderResult { Error=length==0?"TLS 1.2: Server closed connection before HTTP headers":"TLS 1.2: Invalid HTTP status line" };
     string server=lines.Skip(1).FirstOrDefault(line=>line.StartsWith("Server:",StringComparison.OrdinalIgnoreCase));
     return new WebHeaderResult { Responded=true,Status=status,Server=server==null?null:server.Substring(7).Trim() };
    }
   } catch(Exception error) { return new WebHeaderResult { Error="TLS 1.2: "+error.GetBaseException().Message }; }
  }
 }
 static string ReadWebHeaderFallback(string url,string hostname) {
  string detected;
  return ProbeWebHeader(url,hostname,out detected);
 }
 static string ProbeWebHeader(string url,string hostname,out string detected) {
  detected=null;
  WebHeaderResult response=null; var errors=new System.Collections.Generic.List<string>();
  string[] names=string.IsNullOrEmpty(hostname)?new string[]{null}:new[]{null,hostname};
  foreach(string name in names) {
   bool headResponded=false;
   foreach(string method in new[]{"HEAD","HEAD","GET"}) {
    // HEAD nur bei einem Verbindungsfehler wiederholen; sonst direkt GET versuchen.
    if(method=="HEAD" && headResponded) continue;
    var attempt=RequestWebHeader(url,method,name);
    string source=method+(name==null?"":" Host/SNI="+name);
    if(!string.IsNullOrWhiteSpace(attempt.Server)) { detected=url; return url+" - "+attempt.Server+" ["+source+"]"; }
    if(attempt.Responded) { response=attempt; if(method=="HEAD") headResponded=true; }
    else errors.Add(attempt.Error);
    if(!attempt.Responded && method=="HEAD" && attempt.Error.StartsWith("TLS-Handshake",StringComparison.Ordinal)) headResponded=true;
   }
  }
  if(response==null && new Uri(url).Scheme=="https") {
   var tlsAttempt=RequestWebHeader(url,"HEAD",hostname,true);
   if(!string.IsNullOrWhiteSpace(tlsAttempt.Server)) { detected=url; return url+" - "+tlsAttempt.Server+" [TLS 1.2]"; }
   if(tlsAttempt.Responded) response=tlsAttempt;
   else {
    errors.Add(tlsAttempt.Error);
    foreach(bool http10 in new[]{false,true}) {
     foreach(string name in names) {
      var get=RequestTls12Header(url,name,"GET",http10);
      if(!string.IsNullOrWhiteSpace(get.Server)) { detected=url; return url+" - "+get.Server+" [TLS GET / HTTP/"+(http10?"1.0":"1.1")+"]"; }
      if(get.Responded) response=get;
      else errors.Add(get.Error);
     }
     if(response!=null) break;
    }
    if(response==null) {
    // Die Portnummer beweist kein HTTPS: auf demselben Zielport HTTP testen.
    var plain=new UriBuilder(url); plain.Scheme="http"; plain.Port=new Uri(url).Port;
    foreach(string method in new[]{"HEAD","GET"}) {
     var attempt=RequestWebHeader(plain.Uri.AbsoluteUri,method,hostname);
     if(!string.IsNullOrWhiteSpace(attempt.Server)) { detected=plain.Uri.AbsoluteUri; return detected+" - "+attempt.Server+" [HTTP fallback / "+method+"]"; }
     if(attempt.Responded) response=attempt;
     else errors.Add(attempt.Error);
    }
    if(response!=null) url=plain.Uri.AbsoluteUri;
    }
   }
  }
  if(response!=null) detected=url;
  if(response!=null) return url+" - "+ServiceText("HTTP erkannt; kein Server-Header (Typ unbekannt)","HTTP detected; no Server header (type unknown)")+" [HTTP "+response.Status+"]";
  return url+" - "+string.Join(" | ",errors.Distinct());
 }
 static void StartHostServices(Host host) {
  string ports=host.Ports??"";
  lock(host) {
   if(host.ServicePorts==ports) return;
   host.ServicePorts=ports;
   host.WebLinks=null; host.SmbPaths=null; host.WebServers=null; host.SmbShares=null;
  }
  int[] open=ports.Split(',').Select(value=>{ int port; return int.TryParse(value.Trim(),out port)?port:0; }).ToArray();
  int[] web=open.Where(port=>new[]{80,443,8000,8006,8080,8443,8888}.Contains(port)).ToArray();
  if(web.Length>0) {
   host.WebServers=ServiceText("Wird ermittelt ...","Loading ...");
   var links=new string[web.Length];
   var results=web.Select(port=>port+": "+ServiceText("Wird ermittelt ...","Loading ...")).ToArray();
   Task.Run(async ()=> {
    await Task.WhenAll(web.Select(async (port,index)=> {
     await webProbeSlots.WaitAsync(); string result, detected=null;
     try { result=ProbeWebHeader((port==443 || port==8443 || port==8006?"https":"http")+"://"+host.IP+":"+port+"/",UsableHostName(host.DNS)?host.DNS.TrimEnd('.'):null,out detected); }
     catch(Exception error) { result=port+": "+error.Message; }
     finally { webProbeSlots.Release(); }
     lock(results) {
      results[index]=result; links[index]=detected;
      if(host.ServicePorts==ports) {
       host.WebLinks=links.Where(link=>link!=null).ToArray();
       host.WebServers=string.Join("\n",results);
      }
     }
    }));
   });
  }
  if(open.Contains(445) || open.Contains(139)) {
   host.SmbShares=ServiceText("Wird ermittelt ...","Loading ...");
   var paths=new System.Collections.Generic.List<string>();
   Task.Run(async ()=> {
    var probe=Task.Run(async ()=> {
     await shareProbeSlots.WaitAsync();
     try { return ReadShares(host.IP,paths.Add); } catch(Exception error) { return error.Message; }
     finally { shareProbeSlots.Release(); }
    });
    bool completed=await Task.WhenAny(probe,Task.Delay(7000))==probe;
    if(host.ServicePorts==ports) {
     host.SmbPaths=completed?paths.ToArray():null;
     host.SmbShares=completed?await probe:ServiceText("Zeitueberschreitung bei der Freigabenabfrage","Share enumeration timed out");
    }
   });
  }
 }
 static DetailLine[] HostDetailLines(Host host,int width) {
  return HostGeneralDetailLines(host,width).Concat(HostServiceDetailLines(host,width)).ToArray();
 }
 static DetailLine[] HostGeneralDetailLines(Host host,int width) {
  var lines=new System.Collections.Generic.List<DetailLine>();
  AddDetail(lines,T("IP-Adresse"),host.IP,width);
  AddDetail(lines,T("DNS-Name"),DisplayHostName(host),width);
  AddDetail(lines,T("Namensquelle"),T(host.NameSource),width);
  AddDetail(lines,T("MAC-Adresse"),DisplayStatus(host.MAC),width);
  AddDetail(lines,T("Hersteller"),DisplayStatus(host.Vendor),width);
  AddDetail(lines,"Ping",FormatPing(host.Ping),width);
  AddDetail(lines,T("TCP-Ports"),DisplayStatus(host.Ports),width);
  if(host.UdpPorts!=null) AddDetailList(lines,"UDP-Ports",host.UdpPorts,width);
  return lines.ToArray();
 }
 static DetailLine[] HostServiceDetailLines(Host host,int width) {
  var lines=new System.Collections.Generic.List<DetailLine>();
  if(host.WebServers!=null) foreach(string value in host.WebServers.Split('\n')) AddDetail(lines,ServiceText("Webserver","Web server"),value,width);
  if(host.SmbShares!=null) AddDetailList(lines,ServiceText("SMB-Freigaben","SMB shares"),host.SmbShares,width);
  return lines.ToArray();
 }
 static void AddDetailList(System.Collections.Generic.List<DetailLine> lines,string label,string values,int width) {
  lines.Add(new DetailLine(label+":",true));
  foreach(string value in values.Split('\n')) {
   string clean=ExportTextValue(value);
   for(int offset=0;offset<clean.Length;offset+=Math.Max(1,width)) lines.Add(new DetailLine(clean.Substring(offset,Math.Min(Math.Max(1,width),clean.Length-offset))));
  }
  lines.Add(new DetailLine(""));
 }
 static void DrawHostDetails(int w,int h) {
  StartHostServices(detailHost);
  for(int row=0;row<headerLines.Length;row++) HeadingLine(row,row==0?ModeHeader(w):headerLines[row],w);
  int top=headerLines.Length;
  Line(top,new string('\u2500',w),w);
  HeadingLine(top+1,"  "+T("HOSTDETAILS")+" - "+detailHost.IP,w);
  Line(top+2,"",w);
  int right=w/2+2,leftWidth=w/2-4,rightWidth=w-right-2;
  var leftLines=HostGeneralDetailLines(detailHost,leftWidth);
  var rightLines=HostServiceDetailLines(detailHost,rightWidth);
  int rows=Math.Max(1,h-top-7);
  hostDetailScroll=Math.Max(0,Math.Min(hostDetailScroll,Math.Max(0,Math.Max(leftLines.Length,rightLines.Length)-rows)));
  for(int row=0;row<rows;row++) {
   int index=hostDetailScroll+row;
   Console.SetCursorPosition(0,top+3+row); Console.Write("  ");
   WriteHostDetailCell(leftLines,index,leftWidth);
   Console.Write(new string(' ',right-leftWidth-2));
   WriteHostDetailCell(rightLines,index,rightWidth);
   Console.Write("  ");
  }
  Line(h-4,T("Space / Enter / Esc: zurueck | Hoch/Runter, Bild auf/ab: Details scrollen"),w);
  Line(h-3,new string('\u2500',w),w); Line(h-2,"",w); DrawMenu(h-1,w);
  DrawDialog(w,h);
 }
 static void WriteHostDetailCell(DetailLine[] lines,int index,int width) {
  string text=Cell(index<lines.Length?lines[index].Text:"",width);
  if(index<lines.Length && lines[index].IsLabel) WriteHeading(text); else Console.Write(text);
 }
 // Zeichnet die IP-Oberflaeche oder delegiert an mDNS und aktive Dialoge.
 static void Draw(string input) {
  if(!themePicker) { DrawContent(input); return; }
  if(themePreviewDirty || themePreviewWidth!=Console.WindowWidth || themePreviewHeight!=Console.WindowHeight) {
   string title=dialogTitle,message=dialogMessage;
   try {
    themePicker=false; dialogTitle=themePreviousTitle; dialogMessage=themePreviousMessage;
    DrawContent(input);
   } finally { themePicker=true; dialogTitle=title; dialogMessage=message; }
   themePreviewDirty=false;
   themePreviewWidth=Console.WindowWidth; themePreviewHeight=Console.WindowHeight;
  }
  DrawDialog(Console.WindowWidth,Console.WindowHeight);
 }
 static void DrawContent(string input) {
  UpdateOsDialog();
  ResumeContinuousPingIfReady();
  int w=Math.Max(1,Console.WindowWidth-1),h=Console.WindowHeight;
  int headerHeight=headerLines.Length,minHeight=headerHeight+15;
  if(w<89 || h<minHeight) {
   InvalidateMdnsFrame();
   renderedModal=null; renderedIdleFrame=null;
   Line(0,T("Fenster bitte auf mindestens 90 x ")+minHeight+T(" vergroessern."),w);
   return;
  }
  string modal=portScan!=null?"PORTSCAN":exportPopup?"EXPORT":continuousPing!=null?"PING":ouiPopup?"OUI":cidrInput!=null?"CIDR:"+cidrInput:dialogMessage!=null?dialogTitle+":"+dialogMessage:null;
  if(!listenMode && !mdnsMode && detailHost!=null && portScan==null && !exportPopup && continuousPing==null && !ouiPopup && cidrInput==null) { DrawHostDetails(w,h); return; }
  if(ReuseModalFrame(modal,w,h)) return;
  if(listenMode) { DrawArp(w,h); return; }
  if(mdnsMode) {
   DrawMdns(w,h);
   renderedModal=modal; renderedWidth=w; renderedHeight=h; renderedCidrIndex=cidrIndex;
   return;
  }
  string idleKey=IdleFrameKey(input,w,h);
  if(modal==null && !hasScan && renderedModal==null && renderedIdleFrame==idleKey) return;
  var list=SortedHosts(); SyncHostDetails(list);
  bool rightPane=!hasScan || detailHost!=null;
  int left=rightPane?LeftWidth(w):w,rows=h-headerHeight-10,offset=Math.Max(0,selected-rows+1);
  int[] columnSizes=ListColumnWidths(list,left-2);
  for(int row=0;row<headerHeight;row++) {
   string header=row==0?ModeHeader(w):headerLines[row];
   HeadingLine(row,header,w);
  }
  Line(headerHeight,new string('\u2500',w),w); SearchLine(headerHeight+1,searchEditing?T("Suchen: ")+searchText+"_":T("Subnetz: ")+input+"_",w); Line(headerHeight+2,rightPane?new string('\u2500',left)+"\u252c"+new string('\u2500',w-left-1):new string('\u2500',w),w);
  string heading=Cell((hasScan?"  "+Columns("IP","DNS","MAC",T("HERSTELLER"),left-2,columnSizes):new string(' ',left))+(rightPane?"\u2502 "+(hasScan?T("HOSTDETAILS"):""):""),w);
  if(hasScan) {
   int gapSpace=Math.Max(0,left-2-columnSizes.Sum()),columnX=2;
   for(int column=0;column<sortColumn;column++) columnX+=columnSizes[column]+gapSpace/3+(column<gapSpace%3?1:0);
   int columnEnd=columnX+columnSizes[sortColumn];
   ConsoleColor foreground=ThemeForeground,background=ThemeBackground;
   try {
    Console.SetCursorPosition(0,headerHeight+3);
    ThemeForeground=themeIndex==0?foreground:HeadingColor;
    Console.Write(heading.Substring(0,columnX));
    ThemeForeground=themeIndex==0?MenuBackground:ConsoleColor.Yellow;
    Console.Write(heading.Substring(columnX,columnEnd-columnX));
    ThemeForeground=themeIndex==0?foreground:HeadingColor;
    Console.Write(heading.Substring(columnEnd));
   } finally { ThemeForeground=foreground; ThemeBackground=background; }
  } else Line(headerHeight+3,heading,w);
  Line(headerHeight+4,new string(' ',left)+(rightPane?"\u2502":""),w);
  if(!hasScan) {
   // Nur den Titel akzentuieren; der Trenner gehoert zum normalen Rahmen.
   Console.SetCursorPosition(left+2,headerHeight+4);
   WriteHeading(Cell(T("CIDR Subnetzmaske"),Math.Max(0,w-left-2)));
  }
  var wrapped=new System.Collections.Generic.List<DetailLine>();
  if(detailHost!=null) wrapped.AddRange(HostDetailLines(detailHost,w-left-2));
  string[] masks=SubnetMasks();
  int maskRows=Math.Max(1,rows-2);
  maskScroll=Math.Max(0,Math.Min(maskScroll,masks.Length-maskRows));
  for(int r=0;r<rows;r++) {
   int i=offset+r;
   string item=i<list.Length?HostRow(list[i],left,columnSizes):new string(' ',left);
   Console.SetCursorPosition(0,headerHeight+5+r);
   ConsoleColor foreground=ThemeForeground,background=ThemeBackground;
   try {
    if(i<list.Length && i==selected) {
     BeginSelectedRow(foreground,background);
    }
    if(i<list.Length) WriteHostRow(item,list[i],columnSizes,i==selected);
    else Console.Write(item);
   } finally {
    if(i<list.Length && i==selected) EndSelectedRow(foreground,background);
    else { ThemeForeground=foreground; ThemeBackground=background; }
   }
   string rightText;
   if(!hasScan) {
    rightText=r==rows-1?"":maskScroll+r<masks.Length?masks[maskScroll+r]:"";
   } else rightText=r<wrapped.Count?wrapped[r].Text:"";
   if(rightPane) {
    Console.Write("\u2502 ");
    string detailText=Cell(rightText,Math.Max(0,w-left-2));
    if(hasScan && r<wrapped.Count && wrapped[r].IsLabel) WriteHeading(detailText);
    else Console.Write(detailText);
   }
  }
  string state=continuousMode?ServiceText("Continuous | F3/F9: Stopp","Continuous | F3/F9: stop"):TranslateMessage(message);
  if(scan!=null && scan.IsCompleted) state=scan.IsFaulted?T("Fehler: ")+TranslateMessage(scan.Exception.GetBaseException().Message):cancel.IsCancellationRequested?T("Abgebrochen."):T("Scan abgeschlossen.");
  else if(cancel!=null && cancel.IsCancellationRequested) state=T("Abbruch laeuft ...");
  if(scan!=null && !scan.IsCompleted && !cancel.IsCancellationRequested) {
   char spinner="\u2502/-\\"[(Environment.TickCount & int.MaxValue)/120%4];
   state=T("Scan laeuft ")+spinner;
  }
  int completed=Volatile.Read(ref done),count=total;
  SearchLine(h-5,Cell(searchEditing?"":searchText.Length>0?T("Suchen: ")+searchText+" | "+list.Length+T(" Treffer (Esc: loeschen)"):ouiPopup?"":TranslateMessage(exportMessage),left)+(rightPane?"\u2502":""),w);
  Line(h-4,rightPane?new string('\u2500',left)+"\u2534"+new string('\u2500',w-left-1):new string('\u2500',w),w);
  if(scan!=null && !scan.IsCompleted) DrawProgress(h-3,w,state+ClipboardNotice(),completed,count,list.Length);
  else Line(h-3,state+" \u2502 "+completed+"/"+count+" \u2502 Hosts: "+list.Length+ClipboardNotice(),w);
  Line(h-2,new string('\u2500',w),w);
  DrawMenu(h-1,w);
  DrawDialog(w,h);
  DrawCidr(w,h);
  if(ouiPopup) { renderedOuiProgress=null; DrawOuiPopup(w,h); }
  if(continuousPing!=null) { renderedPingLines=null; DrawContinuousPing(w,h); }
  if(exportPopup) { renderedExportKey=null; DrawExportDialog(w,h); }
  if(portScan!=null) { portScan.Rendered=null; DrawPortScan(w,h); }
  renderedModal=modal;
  renderedWidth=w; renderedHeight=h; renderedCidrIndex=cidrIndex;
  renderedIdleFrame=!hasScan && modal==null?idleKey:null;
 }
 // ARP-Mitschnitt ueber native Betriebssystem-Schnittstellen. Kein aktiver Netzverkehr.
 const int ArpCapacity=10000;
 static bool listenMode;
 static string arpSearch="";
 static int arpScroll;
 static long arpReceived;
 static CancellationTokenSource arpCancel;
 static Task arpTask;
 static volatile string arpStatus="";
 static readonly object arpLock=new object();
 static readonly System.Collections.Generic.Queue<ArpRequest> arpRequests=new System.Collections.Generic.Queue<ArpRequest>();
 sealed class ArpRequest { public string Time,Adapter,SenderIP,SenderMAC,TargetIP; }
 // Akzeptiert nur vollstaendige Ethernet/IPv4-ARP-Requests mit bis zu zwei VLAN-Tags.
 static ArpRequest ParseArpRequest(byte[] frame,string adapter,DateTime time,string[] localMacs) {
  if(frame==null || frame.Length<14) return null;
  int offset=14,type=(frame[12]<<8)|frame[13],tags=0;
  while(type==0x8100 || type==0x88a8) {
   if(++tags>2 || frame.Length<offset+4) return null;
   type=(frame[offset+2]<<8)|frame[offset+3]; offset+=4;
  }
  if(type!=0x0806 || frame.Length<offset+28) return null;
  if(frame[offset]!=0 || frame[offset+1]!=1 || frame[offset+2]!=8 || frame[offset+3]!=0 ||
     frame[offset+4]!=6 || frame[offset+5]!=4 || frame[offset+6]!=0 || frame[offset+7]!=1) return null;
  string source=BitConverter.ToString(frame,6,6),mac=BitConverter.ToString(frame,offset+8,6);
  if(localMacs.Any(m=>string.Equals(m,source,StringComparison.OrdinalIgnoreCase) || string.Equals(m,mac,StringComparison.OrdinalIgnoreCase))) return null;
  return new ArpRequest { Time=time.ToString("HH:mm:ss.fff"),Adapter=adapter,SenderMAC=mac.Replace('-',':'),
   SenderIP=new IPAddress(frame.Skip(offset+14).Take(4).ToArray()).ToString(),TargetIP=new IPAddress(frame.Skip(offset+24).Take(4).ToArray()).ToString() };
 }
 // Begrenzt den Speicherverbrauch; wiederholte Requests bleiben einzelne Tabellenzeilen.
 static void AddArpRequest(ArpRequest request) {
  if(request==null) return;
  lock(arpLock) { if(arpRequests.Count==ArpCapacity) arpRequests.Dequeue(); arpRequests.Enqueue(request); arpReceived++; }
 }
 static ArpRequest[] FilteredArp() {
  lock(arpLock) return arpRequests.Where(r=>searchText.Length==0 || ContainsSearch(r.Time) || ContainsSearch(r.Adapter) || ContainsSearch(r.SenderIP) || ContainsSearch(r.SenderMAC) || ContainsSearch(r.TargetIP)).ToArray();
 }
 // Plattformbackend; Fehler bleiben in der Ansicht sichtbar und beenden den Prozess nicht.
 static void CaptureArp(CancellationToken token) {
  try {
   if(IsWindows) CaptureWindowsArp(token); else CaptureLinuxArp(token);
   arpStatus=English?"Listening stopped.":"Mitschnitt gestoppt.";
  } catch(DllNotFoundException) { arpStatus="PktMon API unavailable. A current Windows 11 / Server with Pktmonapi.dll is required."; }
    catch(EntryPointNotFoundException) { arpStatus="PktMon streaming API unavailable. Update Windows."; }
    catch(Exception error) { arpStatus=T("Fehler: ")+error.Message; }
 }

 // Windows PktMon API: separate session and stream; existing captures stay untouched.
 [UnmanagedFunctionPointer(CallingConvention.Winapi)]
 delegate void PktDataCallback(IntPtr context,IntPtr descriptor);
 [UnmanagedFunctionPointer(CallingConvention.Winapi)]
 delegate void PktEventCallback(IntPtr context,IntPtr info,int kind);
 [StructLayout(LayoutKind.Sequential)]
 struct PktStreamConfig { public IntPtr Context,EventCallback,DataCallback; public ushort BufferMultiplier,TruncationSize; }
 [StructLayout(LayoutKind.Sequential)]
 struct PktData { public IntPtr Data; public uint Size,MetadataOffset,PacketOffset,PacketLength,MissedWrite,MissedRead; }
 // Read only the fixed-width prefix; subsequent native padding and timestamps
 // are not interpreted. Both platforms display local application reception time.
 [StructLayout(LayoutKind.Explicit,Size=20)]
 struct PktMetadata {
  [FieldOffset(0)] public ulong Group;
  [FieldOffset(8)] public ushort Count;
  [FieldOffset(10)] public ushort Appearance;
  [FieldOffset(12)] public ushort Direction;
  [FieldOffset(14)] public ushort Type;
  [FieldOffset(16)] public ushort Component;
  [FieldOffset(18)] public ushort Edge;
 }
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
 static extern IntPtr LoadLibraryEx(string path,IntPtr file,uint flags);
 [DllImport("Pktmonapi.dll",ExactSpelling=true)]
 static extern int PacketMonitorInitialize(uint version,IntPtr reserved,out IntPtr handle);
 [DllImport("Pktmonapi.dll",ExactSpelling=true,CharSet=CharSet.Unicode)]
 static extern int PacketMonitorCreateLiveSession(IntPtr handle,string name,out IntPtr session);
 [DllImport("Pktmonapi.dll",ExactSpelling=true)]
 static extern int PacketMonitorEnumDataSources(IntPtr handle,int kind,byte hidden,UIntPtr capacity,out UIntPtr needed,IntPtr buffer);
 [DllImport("Pktmonapi.dll",ExactSpelling=true)]
 static extern int PacketMonitorAddSingleDataSourceToSession(IntPtr session,IntPtr source);
 [DllImport("Pktmonapi.dll",ExactSpelling=true)]
 static extern int PacketMonitorCreateRealtimeStream(IntPtr handle,ref PktStreamConfig config,out IntPtr stream);
 [DllImport("Pktmonapi.dll",ExactSpelling=true)]
 static extern int PacketMonitorAttachOutputToSession(IntPtr session,IntPtr stream);
 [DllImport("Pktmonapi.dll",ExactSpelling=true)]
 static extern int PacketMonitorSetSessionActive(IntPtr session,byte active);
 [DllImport("Pktmonapi.dll",ExactSpelling=true)]
 static extern void PacketMonitorCloseRealtimeStream(IntPtr stream);
 [DllImport("Pktmonapi.dll",ExactSpelling=true)]
 static extern void PacketMonitorCloseSessionHandle(IntPtr session);
 [DllImport("Pktmonapi.dll",ExactSpelling=true)]
 static extern void PacketMonitorUninitialize(IntPtr handle);
 static void CheckPkt(int result) {
  if(result>=0) return;
  if(result==unchecked((int)0x80070005)) throw new UnauthorizedAccessException(English?"ARP listening requires Run as administrator.":"ARP-Listenmodus: als Administrator starten.");
  throw new InvalidOperationException("PktMon: 0x"+result.ToString("X8")+" "+Marshal.GetExceptionForHR(result).Message);
 }
 // Bounds-check native offsets before copying packet or metadata bytes.
 static ArpRequest ReadPktData(IntPtr pointer,string[] localMacs,System.Collections.Generic.Dictionary<uint,string> labels) {
  var data=(PktData)Marshal.PtrToStructure(pointer,typeof(PktData));
  int size=Marshal.SizeOf(typeof(PktMetadata));
  if(data.Data==IntPtr.Zero || data.Size>16*1024*1024 || data.PacketLength<14 || data.PacketLength>128 ||
    (ulong)data.PacketOffset+data.PacketLength>data.Size || (ulong)data.MetadataOffset+(uint)size>data.Size) return null;
  var meta=(PktMetadata)Marshal.PtrToStructure(IntPtr.Add(data.Data,(int)data.MetadataOffset),typeof(PktMetadata));
  // Rx at a NIC, Ethernet payload only. Excludes Tx and upper-stack duplicate appearances.
  if(meta.Direction!=3 || meta.Type!=1) return null;
  var frame=new byte[data.PacketLength];
  Marshal.Copy(IntPtr.Add(data.Data,(int)data.PacketOffset),frame,0,frame.Length);
  string adapter; if(!labels.TryGetValue(meta.Component,out adapter)) adapter="NIC #"+meta.Component;
  return ParseArpRequest(frame,adapter,DateTime.Now,localMacs);
 }
 static void CaptureWindowsArp(CancellationToken token) {
  IntPtr module=LoadLibraryEx(System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"Pktmonapi.dll"),IntPtr.Zero,0x800);
  if(module==IntPtr.Zero) throw new DllNotFoundException();
  IntPtr handle=IntPtr.Zero,session=IntPtr.Zero,stream=IntPtr.Zero,buffer=IntPtr.Zero;
  string callbackError=null; long missed=0;
  var adapterLabels=new System.Collections.Generic.Dictionary<uint,string>();
  string[] localMacs=NetworkInterface.GetAllNetworkInterfaces().Select(n=>BitConverter.ToString(n.GetPhysicalAddress().GetAddressBytes())).ToArray();
  PktDataCallback dataCallback=(context,pointer)=>{
   try {
    var data=(PktData)Marshal.PtrToStructure(pointer,typeof(PktData));
    Interlocked.Add(ref missed,(long)data.MissedRead+data.MissedWrite);
    if(!token.IsCancellationRequested) AddArpRequest(ReadPktData(pointer,localMacs,adapterLabels));
   } catch(Exception error) { Interlocked.CompareExchange(ref callbackError,error.Message,null); }
  };
  PktEventCallback eventCallback=(context,info,kind)=>{
   if(kind==2) Interlocked.CompareExchange(ref callbackError,"PktMon stream failed.",null);
  };
  try {
   CheckPkt(PacketMonitorInitialize(0x00010000,IntPtr.Zero,out handle));
   CheckPkt(PacketMonitorCreateLiveSession(handle,"KubScan-"+Guid.NewGuid().ToString("N"),out session));
   var sources=SelectPktAdapters(GetPktSources(handle,out buffer),arpAdapterKey);
   adapterLabels=PktAdapterLabels(sources,ArpNicInfos());
   int count=sources.Length;
   foreach(var source in sources) CheckPkt(PacketMonitorAddSingleDataSourceToSession(session,source.Pointer));
   var config=new PktStreamConfig { BufferMultiplier=4,TruncationSize=128,
    DataCallback=Marshal.GetFunctionPointerForDelegate(dataCallback),EventCallback=Marshal.GetFunctionPointerForDelegate(eventCallback) };
   CheckPkt(PacketMonitorCreateRealtimeStream(handle,ref config,out stream));
   CheckPkt(PacketMonitorAttachOutputToSession(session,stream));
   CheckPkt(PacketMonitorSetSessionActive(session,1));
   while(!token.WaitHandle.WaitOne(100)) {
    string error=Volatile.Read(ref callbackError); if(error!=null) throw new InvalidOperationException(error);
    arpStatus="PktMon | "+count+" NICs | "+(English?"Missed packets: ":"Verpasste Pakete: ")+Interlocked.Read(ref missed);
   }
  } finally {
   if(session!=IntPtr.Zero) PacketMonitorSetSessionActive(session,0);
   if(stream!=IntPtr.Zero) PacketMonitorCloseRealtimeStream(stream);
   if(session!=IntPtr.Zero) PacketMonitorCloseSessionHandle(session);
   if(handle!=IntPtr.Zero) PacketMonitorUninitialize(handle);
   if(buffer!=IntPtr.Zero) Marshal.FreeHGlobal(buffer);
   GC.KeepAlive(dataCallback); GC.KeepAlive(eventCallback);
   FreeLibrary(module);
  }
 }
 [DllImport("kernel32.dll")] static extern bool FreeLibrary(IntPtr module);
 // AF_PACKET is part of Linux; no libpcap or external helper is used.
 [DllImport("libc",EntryPoint="socket",SetLastError=true)] static extern int LinuxSocket(int domain,int type,int protocol);
 [DllImport("libc",EntryPoint="recvfrom",SetLastError=true)] static extern IntPtr LinuxReceive(int fd,byte[] data,UIntPtr length,int flags,byte[] address,ref uint addressLength);
 [DllImport("libc",EntryPoint="close",SetLastError=true)] static extern int LinuxClose(int fd);
 [DllImport("libc",EntryPoint="if_indextoname",SetLastError=true)] static extern IntPtr LinuxInterfaceName(uint index,System.Text.StringBuilder name);
 static void CaptureLinuxArp(CancellationToken token) {
  if(Environment.OSVersion.Platform!=PlatformID.Unix || !System.IO.Directory.Exists("/proc/net")) throw new PlatformNotSupportedException("ARP listening supports Windows and Linux.");
  string selectedAdapter=arpAdapterKey;
  uint selectedIndex=selectedAdapter.Length==0?0:LinuxInterfaceIndex(selectedAdapter);
  if(selectedAdapter.Length>0 && selectedIndex==0) throw new InvalidOperationException("Selected adapter is no longer available. Select an adapter again.");
  int fd=LinuxSocket(17,3|0x80000,IPAddress.HostToNetworkOrder((short)3)&0xffff); // AF_PACKET, SOCK_RAW|CLOEXEC, ETH_P_ALL
  if(fd<0) {
   int error=Marshal.GetLastWin32Error();
   if(error==1 || error==13) throw new UnauthorizedAccessException("ARP listening requires root or CAP_NET_RAW (sudo ./Kubscan).");
   throw new System.ComponentModel.Win32Exception(error);
  }
  try {
   if(selectedIndex!=0) {
    byte[] bindAddress=LinuxArpBindAddress(selectedIndex);
    if(LinuxBind(fd,bindAddress,(uint)bindAddress.Length)!=0) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
   }
   var names=new System.Collections.Generic.Dictionary<uint,string>();
   var adapterLabels=ArpNicInfos().ToDictionary(n=>n.Name,n=>AdapterLabel(n.Name,n.Mac),StringComparer.Ordinal);
   string[] localMacs=NetworkInterface.GetAllNetworkInterfaces().Select(n=>BitConverter.ToString(n.GetPhysicalAddress().GetAddressBytes())).ToArray();
   var bytes=new byte[65536]; var address=new byte[20];
   arpStatus="AF_PACKET | "+(English?"Listening ...":"Empfang laeuft ...");
   while(!token.IsCancellationRequested) {
    uint addressLength=20; long length=LinuxReceive(fd,bytes,new UIntPtr((uint)bytes.Length),0x40,address,ref addressLength).ToInt64();
    if(length<0) {
     int error=Marshal.GetLastWin32Error();
     if(error==11 || error==4) { token.WaitHandle.WaitOne(20); continue; }
     throw new System.ComponentModel.Win32Exception(error);
    }
    // sockaddr_ll: hatype at 8, pkttype at 10; Ethernet only, exclude PACKET_OUTGOING.
    if(addressLength<12 || BitConverter.ToUInt16(address,8)!=1 || address[10]==4) continue;
    uint index=BitConverter.ToUInt32(address,4); if(selectedIndex!=0 && index!=selectedIndex) continue; string name;
    if(!names.TryGetValue(index,out name)) {
     var text=new System.Text.StringBuilder(16); name=LinuxInterfaceName(index,text)==IntPtr.Zero?"NIC #"+index:text.ToString(); names[index]=name;
    }
    string label; if(adapterLabels.TryGetValue(name,out label)) name=label;
    AddArpRequest(ParseArpRequest(bytes.Take((int)length).ToArray(),name,DateTime.Now,localMacs));
   }
  } finally { LinuxClose(fd); }
 }


 sealed class ArpAdapterOption { public string Key,Label; }
 static string arpAdapterKey="",arpAdapterLabel="";
 static bool arpAdapterEditing;
 static ArpAdapterOption[] arpAdapterOptions=new ArpAdapterOption[0];
 static int arpAdapterIndex;
 static string ArpAdapterCaption() { return arpAdapterKey.Length==0?(English?"All adapters":"Alle Adapter"):arpAdapterLabel; }

 sealed class PktSource {
  public IntPtr Pointer;
  public string Name;
  public uint Id,SecondaryId;
  public Guid[] InterfaceIds=new Guid[0];
  public string[] Macs=new string[0];
 }
 sealed class ArpNicInfo { public string Id,Name,Mac; }
 static ArpNicInfo[] ArpNicInfos() {
  return NetworkInterface.GetAllNetworkInterfaces().Where(n=>n.GetPhysicalAddress().GetAddressBytes().Length==6)
   .Select(n=>new ArpNicInfo { Id=n.Id,Name=n.Name,Mac=FormatMac(n.GetPhysicalAddress().GetAddressBytes()) }).ToArray();
 }
 static string AdapterLabel(string name,string mac) { return ExportTextValue(name)+" - "+(string.IsNullOrEmpty(mac)?(English?"MAC unavailable":"MAC nicht verfuegbar"):mac); }
 // API v1 source header: WCHAR Name[64], Description[128], then four UINT32s.
 // Bound all reads to the source record. Match only identities actually present
 // in the union; support both packed and naturally aligned union placement.
 static PktSource ReadPktSource(IntPtr pointer,int available) {
  if(available<420) throw new InvalidOperationException("PktMon adapter record is too short.");
  var source=new PktSource { Pointer=pointer,Name=Marshal.PtrToStringUni(IntPtr.Add(pointer,4),64).Split('\0')[0],
   Id=unchecked((uint)Marshal.ReadInt32(pointer,388)),SecondaryId=unchecked((uint)Marshal.ReadInt32(pointer,392)) };
  uint present=unchecked((uint)Marshal.ReadInt32(pointer,400));
  var ids=new System.Collections.Generic.List<Guid>(); var macs=new System.Collections.Generic.List<string>();
  foreach(int offset in new[]{404,408}) {
   if((present&1)!=0 && available>=offset+16) { var bytes=new byte[16]; Marshal.Copy(IntPtr.Add(pointer,offset),bytes,0,16); ids.Add(new Guid(bytes)); }
   if((present&8)!=0 && available>=offset+6) { var bytes=new byte[6]; Marshal.Copy(IntPtr.Add(pointer,offset),bytes,0,6); macs.Add(FormatMac(bytes)); }
  }
  source.InterfaceIds=ids.Distinct().ToArray(); source.Macs=macs.Distinct().ToArray();
  return source;
 }


 // Use the OS JSON reader through reflection so Windows PowerShell Add-Type
 // keeps working without additional compiler references or third-party packages.
 static Type PktJsonType(string name,string modernAssembly,string frameworkAssembly) {
  bool framework=typeof(object).Assembly.GetName().Name=="mscorlib";
  string assembly=framework?frameworkAssembly+", Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089":modernAssembly;
  return Type.GetType(name+", "+assembly,true);
 }
 static object PktJsonDocument(string text) {
  byte[] bytes=System.Text.Encoding.UTF8.GetBytes((text??"").Trim().TrimStart('\uFEFF'));
  if(bytes.Length==0 || bytes.Length>8*1024*1024) throw new FormatException("Invalid PktMon JSON length.");
  Type factory=PktJsonType("System.Runtime.Serialization.Json.JsonReaderWriterFactory","System.Runtime.Serialization.Json","System.Runtime.Serialization");
  Type quotaType=PktJsonType("System.Xml.XmlDictionaryReaderQuotas","System.Runtime.Serialization.Xml","System.Runtime.Serialization");
  object quotas=quotaType.GetProperty("Max",System.Reflection.BindingFlags.Public|System.Reflection.BindingFlags.Static).GetValue(null,null);
  var method=factory.GetMethod("CreateJsonReader",new[]{typeof(byte[]),quotaType});
  using(var reader=(IDisposable)method.Invoke(null,new[]{(object)bytes,quotas})) {
   Type documentType=PktJsonType("System.Xml.XmlDocument","System.Xml.XmlDocument","System.Xml");
   Type readerType=PktJsonType("System.Xml.XmlReader","System.Xml.ReaderWriter","System.Xml");
   object document=Activator.CreateInstance(documentType);
   documentType.GetProperty("XmlResolver").SetValue(document,null,null);
   documentType.GetMethod("Load",new[]{readerType}).Invoke(document,new object[]{reader});
   return document;
  }
 }
 static System.Collections.IEnumerable PktJsonNodes(object node,string path) {
  return (System.Collections.IEnumerable)node.GetType().GetMethod("SelectNodes",new[]{typeof(string)}).Invoke(node,new object[]{path});
 }
 static string PktJsonText(object node,string child) {
  object found=node.GetType().GetMethod("SelectSingleNode",new[]{typeof(string)}).Invoke(node,new object[]{child});
  return found==null?"":(string)found.GetType().GetProperty("InnerText").GetValue(found,null);
 }
 static System.Collections.Generic.Dictionary<uint,PktSource> ParsePktAdapterIdentities(string text) {
  var result=new System.Collections.Generic.Dictionary<uint,PktSource>();
  var conflicts=new System.Collections.Generic.HashSet<uint>();
  var document=PktJsonDocument(text);
  object root=document.GetType().GetProperty("DocumentElement").GetValue(document,null);
  if(root==null || (string)root.GetType().GetMethod("GetAttribute",new[]{typeof(string)}).Invoke(root,new object[]{"type"})!="array") throw new FormatException("PktMon JSON is not a component list.");
  foreach(object component in PktJsonNodes(document,"/root/item/Components/item")) {
   uint id; if(!uint.TryParse(PktJsonText(component,"Id"),out id)) continue;
   var ids=new System.Collections.Generic.List<Guid>(); var macs=new System.Collections.Generic.List<string>();
   foreach(object property in PktJsonNodes(component,"Properties/item")) {
    string name=PktJsonText(property,"Name"),value=PktJsonText(property,"Value");
    Guid guid;
    if(string.Equals(name,"ifGuid",StringComparison.OrdinalIgnoreCase) && Guid.TryParse(value,out guid)) ids.Add(guid);
    if((name.StartsWith("MAC",StringComparison.OrdinalIgnoreCase) || name=="PhysAddress") &&
      System.Text.RegularExpressions.Regex.IsMatch(value,@"^(?:[0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}$")) {
     string mac=value.Replace('-',':').ToUpperInvariant();
     if(mac!="00:00:00:00:00:00") macs.Add(mac);
    }
   }
   if(ids.Count==0 && macs.Count==0) continue;
   PktSource previous;
   if(result.TryGetValue(id,out previous)) { ids.AddRange(previous.InterfaceIds); macs.AddRange(previous.Macs); }
   var entry=new PktSource { Id=id,Name=PktJsonText(component,"Name"),InterfaceIds=ids.Distinct().ToArray(),Macs=macs.Distinct().ToArray() };
   if(entry.InterfaceIds.Length>1 || entry.Macs.Length>1) conflicts.Add(id);
   result[id]=entry;
  }
  foreach(uint id in conflicts) result.Remove(id);
  return result;
 }
 static void MergePktAdapterIdentities(PktSource[] sources,System.Collections.Generic.Dictionary<uint,PktSource> listed) {
  foreach(var source in sources) {
   PktSource identity;
   if(!listed.TryGetValue(source.Id,out identity) && !(source.SecondaryId!=0 && listed.TryGetValue(source.SecondaryId,out identity))) continue;
   if(identity.InterfaceIds.Length==1) source.InterfaceIds=identity.InterfaceIds;
   if(identity.Macs.Length==1) source.Macs=identity.Macs;
  }
 }
 static void EnrichPktAdapterMacs(PktSource[] sources) {
  var info=new System.Diagnostics.ProcessStartInfo {
   FileName=System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"pktmon.exe"),
   Arguments="list --json",UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true
  };
  using(var process=System.Diagnostics.Process.Start(info)) {
   var output=process.StandardOutput.ReadToEndAsync(); var error=process.StandardError.ReadToEndAsync();
   if(!process.WaitForExit(10000)) { process.Kill(); process.WaitForExit(); throw new TimeoutException("PktMon adapter listing timed out."); }
   string text=output.GetAwaiter().GetResult(),detail=error.GetAwaiter().GetResult();
   if(process.ExitCode!=0) throw new InvalidOperationException("PktMon adapter listing: "+detail+" "+text);
   MergePktAdapterIdentities(sources,ParsePktAdapterIdentities(text));
  }
 }

 static bool PktSourceMatches(PktSource source,string key) {
  if(key.StartsWith("guid:",StringComparison.Ordinal)) {
   Guid id; return Guid.TryParse(key.Substring(5),out id) && source.InterfaceIds.Contains(id);
  }
  if(key.StartsWith("mac:",StringComparison.Ordinal)) return source.Macs.Contains(key.Substring(4),StringComparer.OrdinalIgnoreCase);
  return key=="pkt:"+source.Id;
 }
 static PktSource[] SelectPktAdapters(PktSource[] sources,string key) {
  if(key.Length==0) return sources;
  var selected=sources.Where(source=>PktSourceMatches(source,key)).ToArray();
  if(selected.Length!=1) throw new InvalidOperationException(English?"Selected adapter is unavailable or ambiguous. Select it again.":"Adapter nicht verfuegbar oder nicht eindeutig. Bitte erneut auswaehlen.");
  return selected;
 }
 static ArpAdapterOption PktAdapterOption(PktSource source,ArpNicInfo[] nics) {
  var matched=nics.Where(n=>{ Guid id; return Guid.TryParse(n.Id,out id) && source.InterfaceIds.Contains(id); }).ToArray();
  bool byGuid=matched.Length==1;
  if(!byGuid) matched=nics.Where(n=>source.Macs.Contains(n.Mac,StringComparer.OrdinalIgnoreCase)).ToArray();
  if(matched.Length==1) {
   var nic=matched[0]; Guid id;
   string key=byGuid && Guid.TryParse(nic.Id,out id)?"guid:"+id.ToString("D"):"mac:"+nic.Mac;
   return new ArpAdapterOption { Key=key,Label=AdapterLabel(nic.Name,nic.Mac) };
  }
  // Do not attach a friendly name to an adapter that cannot be identified.
  return new ArpAdapterOption { Key="pkt:"+source.Id,Label=AdapterLabel(source.Name+" [PktMon #"+source.Id+"]",null) };
 }

 // Caller owns the native buffer, including when discovery throws.
 static PktSource[] GetPktSources(IntPtr handle,out IntPtr buffer) {
  buffer=IntPtr.Zero; UIntPtr needed;
  int result=PacketMonitorEnumDataSources(handle,1,0,UIntPtr.Zero,out needed,IntPtr.Zero);
  if(result<0 && result!=unchecked((int)0x8007007a)) CheckPkt(result);
  for(int attempt=0;attempt<3;attempt++) {
   ulong capacity=needed.ToUInt64();
   if(capacity<8 || capacity>16*1024*1024) throw new InvalidOperationException("Invalid PktMon adapter list.");
   if(buffer!=IntPtr.Zero) { Marshal.FreeHGlobal(buffer); buffer=IntPtr.Zero; }
   buffer=Marshal.AllocHGlobal((int)capacity);
   result=PacketMonitorEnumDataSources(handle,1,0,new UIntPtr(capacity),out needed,buffer);
   if(result==unchecked((int)0x8007007a)) continue;
   CheckPkt(result);
   int count=Marshal.ReadInt32(buffer),start=IntPtr.Size;
   if(count<1 || (ulong)start+(ulong)count*(uint)IntPtr.Size>Math.Min(capacity,needed.ToUInt64())) throw new InvalidOperationException("No PktMon network adapters.");
   var pointers=new IntPtr[count];
   for(int i=0;i<count;i++) pointers[i]=Marshal.ReadIntPtr(buffer,start+i*IntPtr.Size);
   var records=new PktSource[count];
   long begin=buffer.ToInt64(),end=begin+(long)Math.Min(capacity,needed.ToUInt64());
   for(int i=0;i<count;i++) {
    long address=pointers[i].ToInt64();
    if(address<begin || address>=end) throw new InvalidOperationException("Invalid PktMon source pointer.");
    long next=pointers.Select(p=>p.ToInt64()).Where(value=>value>address && value<=end).DefaultIfEmpty(end).Min();
    records[i]=ReadPktSource(pointers[i],checked((int)(next-address)));
   }
   EnrichPktAdapterMacs(records);
   return records;
  }
  throw new InvalidOperationException("Network adapter list changed. Retry capture.");
 }
 static ArpAdapterOption[] DiscoverArpAdapters() {
  var options=new System.Collections.Generic.List<ArpAdapterOption>();
  options.Add(new ArpAdapterOption { Key="",Label=English?"All adapters":"Alle Adapter" });
  if(IsWindows) {
   IntPtr module=LoadLibraryEx(System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"Pktmonapi.dll"),IntPtr.Zero,0x800);
   if(module==IntPtr.Zero) throw new InvalidOperationException("PktMon API unavailable.");
   IntPtr handle=IntPtr.Zero,buffer=IntPtr.Zero;
   try {
    CheckPkt(PacketMonitorInitialize(0x00010000,IntPtr.Zero,out handle));
    var nics=ArpNicInfos();
    options.AddRange(GetPktSources(handle,out buffer).Select(source=>PktAdapterOption(source,nics)).OrderBy(option=>option.Label,StringComparer.OrdinalIgnoreCase));
   } finally {
    if(buffer!=IntPtr.Zero) Marshal.FreeHGlobal(buffer);
    if(handle!=IntPtr.Zero) PacketMonitorUninitialize(handle);
    FreeLibrary(module);
   }
  } else {
   foreach(var nic in NetworkInterface.GetAllNetworkInterfaces().Where(n=>n.OperationalStatus==OperationalStatus.Up && n.GetPhysicalAddress().GetAddressBytes().Length==6).OrderBy(n=>n.Name,StringComparer.OrdinalIgnoreCase))
    options.Add(new ArpAdapterOption { Key=nic.Name,Label=AdapterLabel(nic.Name,FormatMac(nic.GetPhysicalAddress().GetAddressBytes())) });
  }
  return options.ToArray();
 }
 static void OpenArpAdapterPicker() {
  try {
   arpAdapterOptions=DiscoverArpAdapters();
   arpAdapterIndex=Math.Max(0,Array.FindIndex(arpAdapterOptions,o=>o.Key==arpAdapterKey));
   arpAdapterEditing=true;
  } catch(Exception error) { dialogTitle="FEHLER"; dialogMessage=error.Message; }
 }
 static void ApplyArpAdapter(ArpAdapterOption option) {
  if(option.Key==arpAdapterKey) return;
  StopArp(); // No old worker can publish packets into the new session.
  arpAdapterKey=option.Key; arpAdapterLabel=option.Label;
  StartArp(true);
 }
 static void HandleArpAdapterKey(ConsoleKeyInfo key) {
  int last=Math.Max(0,arpAdapterOptions.Length-1);
  switch(key.Key) {
   case ConsoleKey.Escape: case ConsoleKey.Tab: arpAdapterEditing=false; break;
   case ConsoleKey.UpArrow: arpAdapterIndex=Math.Max(0,arpAdapterIndex-1); break;
   case ConsoleKey.DownArrow: arpAdapterIndex=Math.Min(last,arpAdapterIndex+1); break;
   case ConsoleKey.Home: arpAdapterIndex=0; break;
   case ConsoleKey.End: arpAdapterIndex=last; break;
   case ConsoleKey.PageUp: arpAdapterIndex=Math.Max(0,arpAdapterIndex-5); break;
   case ConsoleKey.PageDown: arpAdapterIndex=Math.Min(last,arpAdapterIndex+5); break;
   case ConsoleKey.Enter:
    if(arpAdapterOptions.Length>0) ApplyArpAdapter(arpAdapterOptions[arpAdapterIndex]);
    arpAdapterEditing=false; break;
  }
 }
 static void DrawArpAdapterPicker(int width,int height) {
  if(!arpAdapterEditing) return;
  int visible=Math.Max(1,Math.Min(arpAdapterOptions.Length,height-8));
  int boxWidth=Math.Min(width-4,Math.Max(56,arpAdapterOptions.Select(o=>o.Label.Length+4).DefaultIfEmpty(56).Max()));
  int x=(width-boxWidth)/2,y=(height-visible-5)/2,inner=boxWidth-2,offset=Math.Max(0,arpAdapterIndex-visible+1);
  ConsoleColor fg=ThemeForeground,bg=ThemeBackground;
  try {
   ThemeForeground=ConsoleColor.White; ThemeBackground=ConsoleColor.DarkBlue;
   Action<int,string> row=(r,text)=>{ Console.SetCursorPosition(x,y+r); Console.Write("\u2502"+Cell(text,inner)+"\u2502"); };
   Console.SetCursorPosition(x,y); Console.Write("\u250c"+new string('\u2500',inner)+"\u2510");
   row(1,English?" Network adapter":" Netzwerkadapter");
   for(int i=0;i<visible;i++) {
    int index=offset+i; bool active=index==arpAdapterIndex;
    ThemeForeground=active?ConsoleColor.DarkBlue:ConsoleColor.White;
    ThemeBackground=active?ConsoleColor.White:ConsoleColor.DarkBlue;
    row(i+2," "+arpAdapterOptions[index].Label);
   }
   ThemeForeground=ConsoleColor.White; ThemeBackground=ConsoleColor.DarkBlue;
   row(visible+2," "+(arpAdapterIndex+1)+"/"+arpAdapterOptions.Length);
   row(visible+3,English?" Up/Down: choose | Enter: apply | Esc: cancel":" Hoch/Runter: Auswahl | Enter: OK | Esc: Abbruch");
   Console.SetCursorPosition(x,y+visible+4); Console.Write("\u2514"+new string('\u2500',inner)+"\u2518");
  } finally { ThemeForeground=fg; ThemeBackground=bg; }
 }
 [DllImport("libc",EntryPoint="if_nametoindex",SetLastError=true)] static extern uint LinuxInterfaceIndex(string name);
 [DllImport("libc",EntryPoint="bind",SetLastError=true)] static extern int LinuxBind(int fd,byte[] address,uint length);
 static byte[] LinuxArpBindAddress(uint index) {
  var address=new byte[20];
  Array.Copy(BitConverter.GetBytes((ushort)17),0,address,0,2);
  Array.Copy(BitConverter.GetBytes(IPAddress.HostToNetworkOrder((short)3)),0,address,2,2);
  Array.Copy(BitConverter.GetBytes(index),0,address,4,4);
  return address;
 }

 static void StartArp(bool clear) {
  if(arpTask!=null && !arpTask.IsCompleted) return;
  if(arpCancel!=null) arpCancel.Dispose();
  if(clear) { lock(arpLock) { arpRequests.Clear(); arpReceived=0; } arpScroll=0; }
  arpCancel=new CancellationTokenSource(); var token=arpCancel.Token;
  arpStatus=English?"Starting ARP capture ...":"ARP-Mitschnitt startet ...";
  arpTask=Task.Run(()=>CaptureArp(token));
 }
 static void StopArp() {
  if(arpCancel!=null) arpCancel.Cancel();
  if(arpTask!=null) arpTask.GetAwaiter().GetResult();
 }
 // Getrennte Filter und Ergebnisse bleiben beim Moduswechsel erhalten.
 static void ToggleListen() {
  InvalidateMdnsFrame(); renderedIdleFrame=null; renderedModal=null; searchEditing=false;
  if(listenMode) { StopArp(); arpSearch=searchText; searchText=ipSearch; listenMode=false; }
  else {
   if(mdnsMode) { mdnsSearch=searchText; mdnsMode=false; } else ipSearch=searchText;
   searchText=arpSearch; listenMode=true; StartArp(false);
  }
 }
 static void HandleArpKey(ConsoleKeyInfo key) {
  if(key.Key==ConsoleKey.F4) { OpenArpAdapterPicker(); return; }
  int page=Math.Max(1,Console.WindowHeight-headerLines.Length-10),count=FilteredArp().Length;
  switch(key.Key) {
   case ConsoleKey.M: ToggleMdns(); break;
   case ConsoleKey.F1: ShowHelp(); break;
   case ConsoleKey.F2: StartArp(false); break;
   case ConsoleKey.F3: StopArp(); StartArp(true); break;
   case ConsoleKey.F7: searchEditing=true; arpScroll=0; break;
   case ConsoleKey.F9: StopArp(); break;
   case ConsoleKey.Escape: if(searchText.Length>0) searchText=""; else StopArp(); break;
   case ConsoleKey.UpArrow: arpScroll=Math.Min(Math.Max(0,count-page),arpScroll+1); break;
   case ConsoleKey.DownArrow: arpScroll=Math.Max(0,arpScroll-1); break;
   case ConsoleKey.PageUp: arpScroll=Math.Min(Math.Max(0,count-page),arpScroll+page); break;
   case ConsoleKey.PageDown: arpScroll=Math.Max(0,arpScroll-page); break;
   case ConsoleKey.Home: arpScroll=Math.Max(0,count-page); break;
   case ConsoleKey.End: arpScroll=0; break;
  }
 }
 static string renderedArpOverlay;
 // Adapter und Suche teilen sich die Eingabezeile; lange Adapternamen lassen Platz fuer den Filter.
 static string ArpInputLine(int width) {
  string adapter="  Adapter: [ "+ArpAdapterCaption()+" ]";
  if(!searchEditing) return adapter;
  string search=T("Suchen: ")+searchText+"_";
  int adapterWidth=Math.Min(adapter.Length,Math.Max(0,width-Math.Min(search.Length,Math.Max(16,width/2))-3));
  return Cell(adapter,adapterWidth)+" | "+Cell(search,Math.Max(0,width-adapterWidth-3));
 }
 // Chronologische Tabelle; nur geaenderte Zeilen schreiben, damit der Mitschnitt nicht flackert.
 static void DrawArp(int w,int h) {
  string overlay=arpAdapterEditing?"adapter|"+arpAdapterIndex:dialogMessage!=null?"dialog|"+dialogTitle+"|"+dialogMessage:null;
  string overlayKey=overlay==null?null:overlay+"|"+w+"|"+h+"|"+themeIndex+"|"+English;
  if(overlayKey!=null && overlayKey==renderedArpOverlay && mdnsPaintedLayout==null) return;
  renderedArpOverlay=overlayKey;
  BeginMdnsFrame(w,h);
  int top=headerLines.Length;
  for(int r=0;r<top;r++) MdnsHeadingLine(r,r==0?ModeHeader(w):headerLines[r],w);
  MdnsLine(top,new string('\u2500',w),w);
  MdnsSearchLine(top+1,ArpInputLine(w),w);
  MdnsLine(top+2,new string('\u2500',w),w);
  int adapterWidth=Math.Max(8,w-69);
  Func<string[],string> row=c=>"  "+Cell(c[0],12)+"  "+Cell(c[1],adapterWidth)+"  "+Cell(c[2],15)+"  "+Cell(c[3],17)+"  "+Cell(c[4],15);
  MdnsHeadingLine(top+3,row(English?new[]{"Time","Adapter","Sender IP","Sender MAC","Requested IP"}:new[]{"Zeit","Adapter","Absender-IP","Absender-MAC","Angefragt IP"}),w);
  MdnsLine(top+4,"",w);
  var list=FilteredArp(); int rows=Math.Max(1,h-top-10);
  arpScroll=Math.Max(0,Math.Min(arpScroll,Math.Max(0,list.Length-rows)));
  int offset=Math.Max(0,list.Length-rows-arpScroll);
  for(int r=0;r<rows;r++) { int index=offset+r; var e=index<list.Length?list[index]:null; MdnsLine(top+5+r,e==null?"":row(new[]{e.Time,ExportTextValue(e.Adapter),e.SenderIP,e.SenderMAC,e.TargetIP}),w); }
  MdnsSearchLine(h-5,!searchEditing && searchText.Length>0?T("Suchen: ")+searchText+" | "+list.Length+T(" Treffer (Esc: loeschen)"):"",w);
  MdnsLine(h-4,new string('\u2500',w),w);
  long received; lock(arpLock) received=arpReceived;
  MdnsLine(h-3,arpStatus+" | "+received+" ARP | "+(English?"Retained: ":"Aufbewahrt: ")+Math.Min(received,ArpCapacity)+"/"+ArpCapacity,w);
  MdnsLine(h-2,new string('\u2500',w),w); MdnsMenu(h-1,w);
  if(overlay!=null) { DrawArpAdapterPicker(w,h); DrawDialog(w,h); InvalidateMdnsFrame(); renderedArpOverlay=overlayKey; }
 }

 static bool mdnsMode;
 static string ipSearch="",mdnsSearch="";
 static int mdnsSelected,mdnsSort;
 static MdnsEntry mdnsDetail;
 static int mdnsDetailScroll;
 static CancellationTokenSource mdnsCancel;
 static Task mdnsTask;
 static volatile string mdnsStatus="";
 static readonly object mdnsLock=new object();
 static readonly System.Collections.Generic.Dictionary<string,MdnsEntry> mdnsEntries=new System.Collections.Generic.Dictionary<string,MdnsEntry>(StringComparer.OrdinalIgnoreCase);
 sealed class MdnsEntry { public string Identity="",Name="",Type="",Host="",Address="",Text=""; public volatile string MAC="Wird ermittelt ..."; public Task MacLookup; public int Port; }
 sealed class MdnsRecord { public string Name,Target,Text; public int Type,Port; public uint Ttl; }
 // Liest einen vorzeichenlosen 16-Bit-Netzwerkwert mit Paketgrenzenpruefung.
 static int DnsWord(byte[] data,int offset) { if(offset<0 || offset+2>data.Length) throw new FormatException(); return (data[offset]<<8)|data[offset+1]; }
 // Liest DNS-Namen samt Kompressionszeigern und begrenzt ungueltige Spruenge.
 static string DnsReadName(byte[] data,ref int offset) {
  int position=offset,end=-1,steps=0; var labels=new System.Collections.Generic.List<string>();
  while(true) {
   if(position>=data.Length || ++steps>128) throw new FormatException();
   int length=data[position++];
   if(length==0) break;
   if((length&192)==192) {
    if(position>=data.Length) throw new FormatException();
    int pointer=((length&63)<<8)|data[position++]; if(end<0) end=position; position=pointer; continue;
   }
   if(length>63 || position+length>data.Length) throw new FormatException();
   labels.Add(System.Text.Encoding.UTF8.GetString(data,position,length)); position+=length;
  }
  offset=end<0?position:end; return string.Join(".",labels)+".";
 }
 // Validiert DNS-Paketgrenzen und extrahiert PTR-, SRV-, TXT- und Adressdatensaetze.
 static MdnsRecord[] ParseMdns(byte[] data) {
  if(data.Length<12 || (data[2]&128)==0) return new MdnsRecord[0];
  int offset=12,questions=DnsWord(data,4),count=DnsWord(data,6)+DnsWord(data,8)+DnsWord(data,10);
  var result=new System.Collections.Generic.List<MdnsRecord>();
  for(int i=0;i<questions;i++) { DnsReadName(data,ref offset); offset+=4; if(offset>data.Length) throw new FormatException(); }
  for(int i=0;i<count;i++) {
   string name=DnsReadName(data,ref offset); int type=DnsWord(data,offset),recordClass=DnsWord(data,offset+2)&32767;
   if(offset+10>data.Length) throw new FormatException();
   uint ttl=((uint)data[offset+4]<<24)|((uint)data[offset+5]<<16)|((uint)data[offset+6]<<8)|data[offset+7];
   int length=DnsWord(data,offset+8); offset+=10; int end=offset+length; if(end>data.Length) throw new FormatException();
   var record=new MdnsRecord { Name=name,Type=type,Ttl=ttl }; int cursor=offset;
   if(recordClass!=1) { offset=end; continue; }
   if(type==12) record.Target=DnsReadName(data,ref cursor);
   else if(type==33) { if(length<7) throw new FormatException(); record.Port=DnsWord(data,offset+4); cursor+=6; record.Target=DnsReadName(data,ref cursor); }
   else if((type==1 && length==4)||(type==28 && length==16)) { var bytes=new byte[length]; Array.Copy(data,offset,bytes,0,length); record.Target=new IPAddress(bytes).ToString(); }
   else if(type==16) {
    var parts=new System.Collections.Generic.List<string>();
    while(cursor<end) { int size=data[cursor++]; if(cursor+size>end) throw new FormatException(); parts.Add(System.Text.Encoding.UTF8.GetString(data,cursor,size)); cursor+=size; }
    record.Text=string.Join("; ",parts);
   }
   if(cursor>end) throw new FormatException(); result.Add(record); offset=end;
  }
  return result.ToArray();
 }
 // Erzeugt eine mDNS-Abfrage fuer einen Namen und DNS-Datensatztyp.
 static byte[] MdnsQuery(string name,int type) {
  var bytes=new System.Collections.Generic.List<byte>(new byte[12]); bytes[5]=1;
  foreach(string label in name.TrimEnd('.').Split('.')) { byte[] value=System.Text.Encoding.UTF8.GetBytes(label); if(value.Length==0 || value.Length>63) throw new FormatException(); bytes.Add((byte)value.Length); bytes.AddRange(value); }
  bytes.Add(0); bytes.Add((byte)(type>>8)); bytes.Add((byte)type); bytes.Add(0); bytes.Add(1); return bytes.ToArray();
 }
 // Sucht acht Sekunden auf aktiven IPv4-Multicastadaptern nach DNS-SD-Diensten.
 static void StartMdns() {
  if(mdnsTask!=null && !mdnsTask.IsCompleted) return;
  if(mdnsCancel!=null) mdnsCancel.Dispose();
  mdnsCancel=new CancellationTokenSource(); var token=mdnsCancel.Token;
  lock(mdnsLock) mdnsEntries.Clear(); mdnsDetail=null; mdnsDetailScroll=0; mdnsSelected=0; mdnsStatus="mDNS-Suche laeuft ...";
  mdnsTask=Task.Run(()=>{
   try {
    var addresses=NetworkInterface.GetAllNetworkInterfaces().Where(n=>n.OperationalStatus==OperationalStatus.Up && n.SupportsMulticast && n.NetworkInterfaceType!=NetworkInterfaceType.Loopback).SelectMany(n=>n.GetIPProperties().UnicastAddresses).Where(a=>a.Address.AddressFamily==AddressFamily.InterNetwork).Select(a=>a.Address).Distinct().ToArray();
    if(addresses.Length==0) throw new InvalidOperationException("Kein aktiver IPv4-Multicastadapter gefunden.");
    using(var client=new UdpClient(AddressFamily.InterNetwork)) {
     client.ExclusiveAddressUse=false; client.Client.SetSocketOption(SocketOptionLevel.Socket,SocketOptionName.ReuseAddress,true);
     client.Client.Bind(new IPEndPoint(IPAddress.Any,5353)); client.Client.ReceiveTimeout=200; client.Ttl=255;
     var interfaces=new System.Collections.Generic.List<IPAddress>();
     foreach(var address in addresses) { try { client.JoinMulticastGroup(IPAddress.Parse("224.0.0.251"),address); interfaces.Add(address); } catch(SocketException) {} }
     if(interfaces.Count==0) throw new InvalidOperationException("mDNS-Multicast konnte auf keinem Adapter aktiviert werden.");
     var queries=new System.Collections.Generic.Dictionary<string,byte[]>(StringComparer.OrdinalIgnoreCase);
     Action<string,int> query=(name,type)=>{ string key=name+"|"+type; if(queries.Count<4096 && !queries.ContainsKey(key)) queries.Add(key,MdnsQuery(name,type)); };
     query("_services._dns-sd._udp.local.",12);
     foreach(string service in new[]{"_airplay._tcp.local.","_raop._tcp.local.","_googlecast._tcp.local.","_http._tcp.local.","_https._tcp.local.","_ipp._tcp.local.","_ipps._tcp.local.","_smb._tcp.local.","_ssh._tcp.local.","_workstation._tcp.local.","_hap._tcp.local.","_spotify-connect._tcp.local."}) query(service,12);
     var records=new System.Collections.Generic.Dictionary<string,MdnsRecord>(StringComparer.OrdinalIgnoreCase);
     var sent=new System.Collections.Generic.HashSet<string>(StringComparer.OrdinalIgnoreCase);
     var timer=System.Diagnostics.Stopwatch.StartNew(); long repeatAt=2000;
     while(timer.ElapsedMilliseconds<8000 && !token.IsCancellationRequested) {
      if(timer.ElapsedMilliseconds>=repeatAt) { sent.Clear(); repeatAt+=2000; }
      foreach(var pair in queries.ToArray()) {
       if(token.IsCancellationRequested) break; if(!sent.Add(pair.Key)) continue;
       foreach(var address in interfaces) { try { client.Client.SetSocketOption(SocketOptionLevel.IP,SocketOptionName.MulticastInterface,address.GetAddressBytes()); client.Send(pair.Value,pair.Value.Length,new IPEndPoint(IPAddress.Parse("224.0.0.251"),5353)); } catch(SocketException) {} }
      }
      IPEndPoint source=new IPEndPoint(IPAddress.Any,0); byte[] packet;
      try { packet=client.Receive(ref source); } catch(SocketException error) { if(error.SocketErrorCode==SocketError.TimedOut || error.SocketErrorCode==SocketError.WouldBlock) continue; throw; }
      MdnsRecord[] parsed; try { parsed=ParseMdns(packet); } catch(FormatException) { continue; }
      foreach(var record in parsed) {
       string key=record.Name+"|"+record.Type+((record.Type==12||record.Type==1||record.Type==28)?"|"+record.Target:"");
       if(record.Ttl==0) { records.Remove(key); continue; }
       if(records.Count<16384 || records.ContainsKey(key)) records[key]=record;
       if(record.Type==12 && record.Target!=null) {
        if(record.Name.Equals("_services._dns-sd._udp.local.",StringComparison.OrdinalIgnoreCase)) query(record.Target,12);
        else { query(record.Target,33); query(record.Target,16); }
       } else if(record.Type==33 && record.Target!=null) { query(record.Target,1); query(record.Target,28); }
      }
      var values=records.Values.ToArray();
      lock(mdnsLock) {
       mdnsEntries.Clear();
       foreach(var ptr in values.Where(r=>r.Type==12 && !r.Name.Equals("_services._dns-sd._udp.local.",StringComparison.OrdinalIgnoreCase))) {
        var srv=values.FirstOrDefault(r=>r.Type==33 && r.Name.Equals(ptr.Target,StringComparison.OrdinalIgnoreCase));
        var txt=values.FirstOrDefault(r=>r.Type==16 && r.Name.Equals(ptr.Target,StringComparison.OrdinalIgnoreCase));
        string suffix="."+ptr.Name;
        mdnsEntries[ptr.Target]=new MdnsEntry { Identity=ptr.Target,Name=ptr.Target.EndsWith(suffix,StringComparison.OrdinalIgnoreCase)?ptr.Target.Substring(0,ptr.Target.Length-suffix.Length):ptr.Target,Type=ptr.Name.TrimEnd('.'),Host=srv==null?"":srv.Target.TrimEnd('.'),Port=srv==null?0:srv.Port,Text=txt==null?"":txt.Text,Address=srv==null?"":MdnsAddresses(values,srv.Target) };
       }
      }
     }
    }
    mdnsStatus=token.IsCancellationRequested?"mDNS-Suche abgebrochen.":"mDNS-Suche abgeschlossen.";
   } catch(Exception error) { mdnsStatus="mDNS-Fehler: "+error.Message; }
  });
 }
 // Fasst passende Hostadressen zusammen und stellt IPv4 vor IPv6 dar.
 static string MdnsAddresses(MdnsRecord[] records,string host) {
  return string.Join(", ",records.Where(r=>(r.Type==1||r.Type==28)&&r.Name.Equals(host,StringComparison.OrdinalIgnoreCase)).OrderBy(r=>r.Type==1?0:1).ThenBy(r=>r.Target,StringComparer.OrdinalIgnoreCase).Select(r=>r.Target).Distinct());
 }
 // Kopiert Eintraege unter kurzer Sperre; Filterung und Sortierung laufen ausserhalb der Sperre.
 static MdnsEntry[] SortedMdns() {
  MdnsEntry[] snapshot;
  lock(mdnsLock) snapshot=mdnsEntries.Values.ToArray();
  return snapshot.Where(e=>searchText.Length==0 || ContainsSearch(e.Name) || ContainsSearch(e.Type) ||
   ContainsSearch(e.Host) || ContainsSearch(e.Address) || ContainsSearch(e.Text) || ContainsSearch(e.Port.ToString()))
   .OrderBy(e=>mdnsSort==1?e.Type:mdnsSort==2?e.Host:mdnsSort==3?e.Address:mdnsSort==4?e.Port.ToString("D5"):e.Name,StringComparer.OrdinalIgnoreCase)
   .ThenBy(e=>e.Name,StringComparer.OrdinalIgnoreCase).ToArray();
 }
 // Wechselt den Scanmodus und bewahrt die getrennten IP- und mDNS-Suchfilter.
 static void ToggleMdns() {
  InvalidateMdnsFrame();
  if(listenMode) ToggleListen();
  if(mdnsMode) { mdnsSearch=searchText; searchText=ipSearch; } else { ipSearch=searchText; searchText=mdnsSearch; }
  mdnsMode=!mdnsMode; renderedIdleFrame=null; renderedModal=null;
  if(mdnsMode) StartMdns();
 }
 // Oeffnet oder schliesst die separate mDNS-Detailseite und startet die MAC-Ermittlung.
 static void ConfirmMdnsEntry() {
  if(mdnsDetail!=null) { mdnsDetail=null; return; }
  var list=SortedMdns();
  if(list.Length>0) { mdnsDetail=list[Math.Max(0,Math.Min(mdnsSelected,list.Length-1))]; mdnsDetailScroll=0; ResolveMdnsMac(mdnsDetail); }
 }
 // Ermittelt einmalig im Hintergrund die MAC einer verfuegbaren IPv4-Dienstadresse.
 static void ResolveMdnsMac(MdnsEntry entry) {
  if(entry.MacLookup!=null) return;
  entry.MacLookup=Task.Run(()=>{
   try {
    string unavailable="Nicht verfuegbar (keine IPv4-Adresse)";
    foreach(string value in entry.Address.Split(',')) {
     IPAddress address;
     if(!IPAddress.TryParse(value.Trim(),out address) || address.AddressFamily!=AddressFamily.InterNetwork) continue;
     string mac=MacAddress(address.ToString());
     if(System.Text.RegularExpressions.Regex.IsMatch(mac,"^([0-9A-F]{2}:){5}[0-9A-F]{2}$")) { entry.MAC=mac; return; }
     unavailable=mac;
    }
    entry.MAC=unavailable;
   } catch { entry.MAC="Nicht verfuegbar (MAC-Abfrage fehlgeschlagen)"; }
  });
 }
 // Erzeugt die vollstaendigen Dienstinformationen inklusive TXT-Metadaten und MAC.
 static DetailLine[] MdnsDetailLines(MdnsEntry entry,int width) {
  var lines=new System.Collections.Generic.List<DetailLine>();
  AddDetail(lines,"Name",entry.Name,width);
  AddDetail(lines,T("Diensttyp"),entry.Type,width);
  AddDetail(lines,"Hostname",entry.Host,width);
  AddDetail(lines,T("IP-Adressen"),entry.Address,width);
  AddDetail(lines,T("MAC-Adresse"),DisplayStatus(entry.MAC),width);
  AddDetail(lines,"Port",entry.Port==0?T("Unbekannt"):entry.Port.ToString(),width);
  AddDetail(lines,T("TXT-Metadaten"),entry.Text,width);
  return lines.ToArray();
 }
 static readonly System.Collections.Generic.Dictionary<int,string> mdnsPaintedRows=new System.Collections.Generic.Dictionary<int,string>();
 static string mdnsPaintedLayout;
 // Gemeinsamer Zeilencache fuer mDNS und ARP; Moduswechsel verwerfen auch Kopfzeile und Menue.
 static void InvalidateMdnsFrame() { mdnsPaintedRows.Clear(); mdnsPaintedLayout=null; renderedArpOverlay=null; }
 // Erkennt geaenderte Fenstermasse oder Sprache und setzt den Zeilencache zurueck.
 static void BeginMdnsFrame(int width,int height) {
  string layout=width+"|"+height+"|"+themeIndex+"|"+English+"|"+listenMode+"|"+mdnsMode;
  if(layout==mdnsPaintedLayout) return;
  mdnsPaintedRows.Clear(); mdnsPaintedLayout=layout;
 }
 // Vergleicht Text und Stil einer Zeile und aktualisiert ihren Cacheeintrag.
 static bool MdnsRowChanged(int row,string text,string style) {
  string key=style+"\u001f"+text,previous;
  if(mdnsPaintedRows.TryGetValue(row,out previous) && previous==key) return false;
  mdnsPaintedRows[row]=key; return true;
 }
 // Erzeugt einen Vergleichsschluessel aus Zeilentyp und aktuellen Konsolenfarben.
 static string MdnsRowStyle(string kind) { return kind+"|"+(int)ThemeForeground+"|"+(int)ThemeBackground; }
 // Schreibt eine normale mDNS-Zeile nur bei geaendertem Inhalt oder Stil.
 static void MdnsLine(int row,string text,int width) {
  if(MdnsRowChanged(row,Cell(text,width),MdnsRowStyle("text"))) Line(row,text,width);
 }
 // Schreibt eine mDNS-Ueberschrift nur bei geaendertem Inhalt oder Stil.
 static void MdnsHeadingLine(int row,string text,int width) {
  if(MdnsRowChanged(row,Cell(text,width),MdnsRowStyle("heading"))) HeadingLine(row,text,width);
 }
 // Aktualisiert die mDNS-Suchzeile nur bei einer sichtbaren Aenderung.
 static void MdnsSearchLine(int row,string text,int width) {
  if(MdnsRowChanged(row,Cell(text,width),MdnsRowStyle("search"))) SearchLine(row,text,width);
 }
 // Zeichnet das mDNS-Menue nur bei geaenderter Beschriftung oder Darstellung.
 static void MdnsMenu(int row,int width) {
  if(MdnsRowChanged(row,"menu",MdnsRowStyle("menu"))) DrawMenu(row,width);
 }

 // Begrenzt die Scrollposition und zeichnet den sichtbaren Ausschnitt der Dienstdetails.
 static void DrawMdnsDetails(int w,int h,int top) {
  MdnsHeadingLine(top+3,"  MDNS-DETAILS",w);
  MdnsLine(top+4,"",w);
  var lines=MdnsDetailLines(mdnsDetail,w-4);
  int rows=Math.Max(1,h-top-10);
  mdnsDetailScroll=Math.Max(0,Math.Min(mdnsDetailScroll,Math.Max(0,lines.Length-rows)));
  for(int r=0;r<rows;r++) {
   int index=mdnsDetailScroll+r;
   string text=index<lines.Length?"  "+lines[index].Text:"";
   if(index<lines.Length && lines[index].IsLabel) MdnsHeadingLine(top+5+r,text,w);
   else MdnsLine(top+5+r,text,w);
  }
  MdnsLine(h-5,T("Space / Enter / Esc: zurueck | Hoch/Runter, Bild auf/ab: Details scrollen"),w);
  MdnsLine(h-4,new string('\u2500',w),w);
  MdnsLine(h-3,TranslateMessage(mdnsStatus)+ClipboardNotice(),w); MdnsLine(h-2,new string('\u2500',w),w); MdnsMenu(h-1,w);
  if(dialogMessage!=null) { DrawDialog(w,h); InvalidateMdnsFrame(); }
 }
 // Zeichnet Diensttabelle oder Detailseite mit gemeinsamer Kopfzeile und mDNS-Menue.
 static void DrawMdns(int w,int h) {
  BeginMdnsFrame(w,h);
  var list=SortedMdns(); mdnsSelected=Math.Max(0,Math.Min(mdnsSelected,list.Length-1));
  for(int r=0;r<headerLines.Length;r++) {
   string header=r==0?ModeHeader(w):headerLines[r];
   MdnsHeadingLine(r,header,w);
  }
  int top=headerLines.Length;
  MdnsLine(top,new string('\u2500',w),w);
  MdnsSearchLine(top+1,searchEditing?T("Suchen: ")+searchText+"_":T("mDNS: Lokales Netz | M: zurueck zum IP-Scan"),w);
  MdnsLine(top+2,new string('\u2500',w),w);
  if(mdnsDetail!=null) { DrawMdnsDetails(w,h,top); return; }
  int available=w-10; int[] widths={available/4,available/4,available/4,available-3*(available/4)-7,7};
  string[] titles={"NAME",T("DIENST"),"HOST","IP","PORT"};
  Func<string[],string> row=c=>"  "+string.Join("  ",c.Select((value,i)=>Cell(ExportTextValue(value),widths[i])));
  string heading=Cell(row(titles),w);
  int columnX=2;
  for(int column=0;column<mdnsSort;column++) columnX+=widths[column]+2;
  var foreground=ThemeForeground; var background=ThemeBackground;
  if(MdnsRowChanged(top+3,heading,MdnsRowStyle("columns:"+mdnsSort))) try {
   Console.SetCursorPosition(0,top+3);
   ThemeForeground=themeIndex==0?foreground:HeadingColor;
   Console.Write(heading.Substring(0,columnX));
   ThemeForeground=themeIndex==0?MenuBackground:ConsoleColor.Yellow;
   Console.Write(heading.Substring(columnX,widths[mdnsSort]));
   ThemeForeground=themeIndex==0?foreground:HeadingColor;
   Console.Write(heading.Substring(columnX+widths[mdnsSort]));
  } finally { ThemeForeground=foreground; ThemeBackground=background; }
  MdnsLine(top+4,"",w);
  int rows=Math.Max(1,h-top-10),offset=Math.Max(0,mdnsSelected-rows+1);
  for(int r=0;r<rows;r++) {
   int index=offset+r; string text="";
   if(index<list.Length) { var e=list[index]; text=row(new[]{e.Name,e.Type,e.Host,e.Address,e.Port==0?"?":e.Port.ToString()}); }
   var fg=ThemeForeground; var bg=ThemeBackground;
   bool isSelected=index<list.Length && index==mdnsSelected;
   try {
    if(isSelected) BeginSelectedRow(fg,bg);
    if(MdnsRowChanged(top+5+r,Cell(text,w),MdnsRowStyle(isSelected?"selected":"text"))) Line(top+5+r,text,w);
   } finally {
    if(isSelected) EndSelectedRow(fg,bg);
    else { ThemeForeground=fg; ThemeBackground=bg; }
   }
  }
  MdnsSearchLine(h-5,searchEditing?"":searchText.Length>0?T("Suchen: ")+searchText+" | "+list.Length+T(" Treffer (Esc: loeschen)"):"",w);
  MdnsLine(h-4,new string('\u2500',w),w);
  MdnsLine(h-3,TranslateMessage(mdnsStatus)+T(" | Dienste: ")+list.Length+ClipboardNotice(),w);
  MdnsLine(h-2,new string('\u2500',w),w);
  MdnsMenu(h-1,w);
  if(dialogMessage!=null) { DrawDialog(w,h); InvalidateMdnsFrame(); }
 }
 // Verarbeitet Suche, Sortierung, Listennavigation und Detailscrollen im mDNS-Modus.
 static void HandleMdnsKey(ConsoleKeyInfo key) {
  if(mdnsDetail!=null && (key.Key==ConsoleKey.Spacebar || key.Key==ConsoleKey.Enter || key.Key==ConsoleKey.Escape)) { mdnsDetail=null; return; }
  int count=SortedMdns().Length;
  int page=(key.Key==ConsoleKey.PageUp || key.Key==ConsoleKey.PageDown)?Math.Max(1,Console.WindowHeight-headerLines.Length-10):1;
  if(mdnsDetail!=null) {
   switch(key.Key) {
    case ConsoleKey.Enter: case ConsoleKey.Escape: mdnsDetail=null; return;
    case ConsoleKey.UpArrow: mdnsDetailScroll=Math.Max(0,mdnsDetailScroll-1); return;
    case ConsoleKey.DownArrow: mdnsDetailScroll++; return;
    case ConsoleKey.PageUp: mdnsDetailScroll=Math.Max(0,mdnsDetailScroll-page); return;
    case ConsoleKey.PageDown: mdnsDetailScroll+=page; return;
    case ConsoleKey.Home: mdnsDetailScroll=0; return;
    case ConsoleKey.End: mdnsDetailScroll=Math.Max(0,MdnsDetailLines(mdnsDetail,Math.Max(1,Console.WindowWidth-5)).Length-page); return;
   }
  }
  switch(key.Key) {
   case ConsoleKey.C: CopySelectedCell(); break;
   case ConsoleKey.Spacebar: case ConsoleKey.Enter: ConfirmMdnsEntry(); break;
   case ConsoleKey.M: ToggleMdns(); break;
   case ConsoleKey.F2: StartMdns(); break;
   case ConsoleKey.F7: searchEditing=true; break;
   case ConsoleKey.F1: ShowHelp(); break;
   case ConsoleKey.Escape: if(searchText.Length>0) searchText=""; else if(mdnsCancel!=null) mdnsCancel.Cancel(); break;
   case ConsoleKey.F9: if(mdnsCancel!=null) mdnsCancel.Cancel(); break;
   case ConsoleKey.UpArrow: mdnsSelected=Math.Max(0,mdnsSelected-1); break;
   case ConsoleKey.DownArrow: mdnsSelected=Math.Min(count-1,mdnsSelected+1); break;
   case ConsoleKey.PageUp: mdnsSelected=Math.Max(0,mdnsSelected-page); break;
   case ConsoleKey.PageDown: mdnsSelected=Math.Min(count-1,mdnsSelected+page); break;
   case ConsoleKey.Home: mdnsSelected=0; break;
   case ConsoleKey.End: mdnsSelected=count-1; break;
   case ConsoleKey.LeftArrow: mdnsSort=Math.Max(0,mdnsSort-1); break;
   case ConsoleKey.RightArrow: mdnsSort=Math.Min(4,mdnsSort+1); break;
  }
 }

 sealed class CommandScanOptions { public string Target; public bool Csv,Txt; }
 // Validiert CLI-Optionen und normalisiert den angegebenen oder automatisch ermittelten Bereich.
 static CommandScanOptions ParseCommandScan(string[] args) {
  if(args==null || args.Length==0 || !string.Equals(args[0],"scan",StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("Aufruf: Kubscan scan [Subnetz/IP-Bereich] [-csv] [-txt] [-OutputPath <directory>]");
  var options=new CommandScanOptions(); var target=new System.Collections.Generic.List<string>();
  foreach(string argument in args.Skip(1)) {
   if(string.Equals(argument,"-csv",StringComparison.OrdinalIgnoreCase)) options.Csv=true;
   else if(string.Equals(argument,"-txt",StringComparison.OrdinalIgnoreCase)) options.Txt=true;
   else if(argument.StartsWith("-") && argument!="-") throw new ArgumentException("Unbekannte Option: "+argument);
   else target.Add(argument);
  }
  string input=string.Join(" ",target).Trim();
  if(input.Length==0) input=DefaultSubnet();
  else if(!input.Contains("/") && !input.Contains("-")) input+="/32";
  options.Target=ScanTargetLabel(input,Parse(input));
  return options;
 }
 // Fuehrt einen automatischen Scan samt optionalem Export aus und liefert definierte Exitcodes.
 public static int RunCommandLine(string[] args,int[] scanPorts) {
  ConsoleCancelEventHandler handler=null;
  try {
   var options=ParseCommandScan(ConfigureStartupArguments(args));
   if(scanPorts==null || scanPorts.Length==0 || scanPorts.Any(p=>p<1 || p>65535)) throw new ArgumentException(T("Ports muessen zwischen 1 und 65535 liegen."));
   ports=scanPorts.Distinct().OrderBy(p=>p).ToArray();
   handler=(sender,eventArgs)=>{ eventArgs.Cancel=true; if(cancel!=null) cancel.Cancel(); };
   Console.CancelKeyPress+=handler;
   Console.WriteLine("Scan: "+options.Target);
   Start(options.Target);
   if(scan==null) throw new InvalidOperationException(message);
   scan.GetAwaiter().GetResult();
   if(cancel.IsCancellationRequested) { Console.Error.WriteLine(T("Scan abgebrochen.")); return 130; }
   Console.WriteLine(T("Scan abgeschlossen. Hosts: ")+hosts.Count);
   if(options.Csv || options.Txt) {
    string stem="IPScan_"+BerlinNow().ToString("yyyy-MM-dd_HH-mm-ss-fff")+"_"+Guid.NewGuid().ToString("N").Substring(0,6);
    if(options.Csv) Console.WriteLine("CSV: "+ExportNamedResults(true,120,stem+".csv"));
    if(options.Txt) Console.WriteLine("TXT: "+ExportNamedResults(false,120,stem+".txt"));
   } else Console.Write(PlainText(hosts.ToArray().OrderBy(pair=>pair.Key).Select(pair=>pair.Value).ToArray(),120));
   return 0;
  } catch(Exception error) { Console.Error.WriteLine(T("Fehler: ")+TranslateMessage(error.Message)); return 1; }
  finally { if(handler!=null) Console.CancelKeyPress-=handler; }
 }

 // Verwaltet die interaktive Ereignisschleife und stellt Konsolenressourcen beim Beenden wieder her.
 public static void Run(string subnet,int[] scanPorts) {
  if(Console.IsInputRedirected || Console.IsOutputRedirected) throw new InvalidOperationException(T("Interaktive Konsole erforderlich."));
  if(scanPorts==null || scanPorts.Length==0 || scanPorts.Any(p=>p<1||p>65535)) throw new ArgumentException("Ports muessen zwischen 1 und 65535 liegen.");
  ports=scanPorts.Distinct().OrderBy(p=>p).ToArray(); string input=string.IsNullOrWhiteSpace(subnet)?DefaultSubnet():subnet; bool visible=IsWindows?Console.CursorVisible:true;
  IntPtr inputHandle=IsWindows?GetStdHandle(-10):IntPtr.Zero; uint originalInputMode=0;
  if(IsWindows) {
  if(!GetConsoleMode(inputHandle,out originalInputMode)) throw new InvalidOperationException(T("Konsoleneingabe nicht verfuegbar."));
  if(!SetConsoleMode(inputHandle,(originalInputMode | 0x98u) & ~0x40u)) throw new InvalidOperationException(T("Mauseingabe konnte nicht aktiviert werden."));
  } else { Console.OutputEncoding=new System.Text.UTF8Encoding(false); Console.Write("\u001b[?1049h\u001b[?1000h\u001b[?1006h"); }
  InitializeThemeOutput();
  if(trueColorEnabled) ApplyTheme(LoadThemeSetting());
  mouseLeftDown=false; keyRepeats=0; linuxPendingKeys.Clear();
  bool exit=false;
  ConsoleCancelEventHandler interactiveCancel=(sender,eventArgs)=>{ eventArgs.Cancel=true; exit=true; };
  Console.CancelKeyPress+=interactiveCancel;
  try { Console.CursorVisible=false; ClearScreen();
   while(!exit) { Draw(input);
    ConsoleKeyInfo k;
    while(TryReadConsoleKey(inputHandle,out k)) {
     if(themePicker) { if(k.Key==ConsoleKey.F10) exit=true; else HandleThemeKey(k.Key); break; }
     if(CanToggleLanguage(k)) { ToggleLanguage(); break; }
     if(k.Key==ConsoleKey.T && !searchEditing && !exportPopup && (portScan==null || !portScan.Editing)) { OpenThemePicker(); break; }
     if(portScan!=null) {
      if(k.Key==ConsoleKey.F10) { ClosePortScan(); exit=true; } else HandlePortScanKey(k);
      break;
     }
     if(exportPopup) {
      if(k.Key==ConsoleKey.F10) exit=true;
      else HandleExportKey(k);
      break;
     }
     if(continuousPing!=null) {
      if(k.Key==ConsoleKey.F10) { StopContinuousPing(true); exit=true; }
      else if(k.Key==ConsoleKey.Escape || k.Key==ConsoleKey.Enter) StopContinuousPing(true);
      else if(k.Key==ConsoleKey.F4) ToggleContinuousPing();
      break;
     }
     if(ouiPopup) {
      if(k.Key==ConsoleKey.F10) exit=true;
      else if((ouiUpdate==null || ouiUpdate.IsCompleted) && (k.Key==ConsoleKey.Enter || k.Key==ConsoleKey.Escape)) { ouiPopup=false; exportMessage=""; }
      break;
     }
     if(cidrInput!=null) {
      if(k.Key==ConsoleKey.F10) exit=true;
      else input=HandleCidr(k.Key,input);
      break;
     }
     if(dialogMessage!=null) {
      if(k.Key==ConsoleKey.Enter || k.Key==ConsoleKey.Escape) { CloseOsDetection(); dialogMessage=null; }
      else if(osSession!=null && (k.Key==ConsoleKey.UpArrow || k.Key==ConsoleKey.DownArrow || k.Key==ConsoleKey.PageUp || k.Key==ConsoleKey.PageDown)) osSession.Scroll+=(k.Key==ConsoleKey.UpArrow?-1:k.Key==ConsoleKey.DownArrow?1:k.Key==ConsoleKey.PageUp?-5:5);
      else if(k.Key==ConsoleKey.F10) exit=true;
      continue;
     }
     if(searchEditing && k.Key>=ConsoleKey.F1 && k.Key<=ConsoleKey.F9 && k.Key!=ConsoleKey.F7) searchEditing=false;
     if(searchEditing) LeaveSearchForNavigation(k.Key);
     if(searchEditing && k.Key!=ConsoleKey.F10) { HandleSearchKey(k); if(mdnsMode) mdnsSelected=0; break; }
     if(listenMode && arpAdapterEditing) { if(k.Key==ConsoleKey.F10) exit=true; else HandleArpAdapterKey(k); break; }
     if(k.Key==ConsoleKey.A) { ToggleListen(); break; }
     if(listenMode) { if(k.Key==ConsoleKey.F10) exit=true; else HandleArpKey(k); break; }
     if(mdnsMode) { if(k.Key==ConsoleKey.F10) exit=true; else HandleMdnsKey(k); break; }
     if(detailHost!=null) {
      int page=Math.Max(1,Console.WindowHeight-headerLines.Length-7);
      if(k.Key==ConsoleKey.Spacebar || k.Key==ConsoleKey.Enter || k.Key==ConsoleKey.Escape) { detailHost=null; renderedModal=null; break; }
      if(k.Key==ConsoleKey.UpArrow || k.Key==ConsoleKey.DownArrow || k.Key==ConsoleKey.PageUp || k.Key==ConsoleKey.PageDown || k.Key==ConsoleKey.Home || k.Key==ConsoleKey.End) {
       hostDetailScroll=k.Key==ConsoleKey.Home?0:k.Key==ConsoleKey.End?int.MaxValue:k.Key==ConsoleKey.UpArrow?Math.Max(0,hostDetailScroll-1):k.Key==ConsoleKey.DownArrow?hostDetailScroll+1:k.Key==ConsoleKey.PageUp?Math.Max(0,hostDetailScroll-page):hostDetailScroll+page;
       break;
      }
     }
     if(!hasScan && (k.Key==ConsoleKey.Home || k.Key==ConsoleKey.End)) {
      maskScroll=k.Key==ConsoleKey.Home?0:SubnetMasks().Length;
      break;
     }
     if(!hasScan && (k.Key==ConsoleKey.PageUp || k.Key==ConsoleKey.PageDown)) {
      maskScroll+=(k.Key==ConsoleKey.PageUp?-1:1)*Math.Max(1,Console.WindowHeight-headerLines.Length-12);
      break;
     }
     switch(k.Key) {
      case ConsoleKey.M: ToggleMdns(); break;
      case ConsoleKey.C: CopySelectedCell(); break;
      case ConsoleKey.O: OpenOsDetection(); break;
      case ConsoleKey.S: OpenPortScan(false); break;
      case ConsoleKey.P: OpenPortScan(true); break;
      case ConsoleKey.U: OpenUdpScan(); break;
      case ConsoleKey.F1: ShowHelp(); break;
      case ConsoleKey.F2: case ConsoleKey.Enter: Start(input); break;
      case ConsoleKey.F3: StartContinuous(input); break;
      case ConsoleKey.F4: StartContinuousPing(); break;
      case ConsoleKey.F7: searchEditing=true; break;
      case ConsoleKey.F8: UpdateOui(); break;
      case ConsoleKey.F9: if(cancel!=null) cancel.Cancel(); break;
      case ConsoleKey.F5: Export(true); break;
      case ConsoleKey.F6: Export(false); break;
      case ConsoleKey.F10: exit=true; break;
      case ConsoleKey.Escape: if(detailHost!=null) detailHost=null; else if(searchText.Length>0) { searchText=""; selected=0; } else if(cancel!=null) cancel.Cancel(); break;
      case ConsoleKey.Spacebar: if(hasScan) ConfirmSelectedHost(); break;

      case ConsoleKey.LeftArrow: ChangeSortColumn(-1); break;
      case ConsoleKey.RightArrow: ChangeSortColumn(1); break;
      case ConsoleKey.Home: selected=0; break;
      case ConsoleKey.End: selected=Math.Max(0,SortedHosts().Length-1); break;
      case ConsoleKey.PageUp: selected=Math.Max(0,selected-Math.Max(1,Console.WindowHeight-headerLines.Length-10)); break;
      case ConsoleKey.UpArrow: selected=Math.Max(0,selected-1); break;
      case ConsoleKey.PageDown: selected=Math.Min(Math.Max(0,SortedHosts().Length-1),selected+Math.Max(1,Console.WindowHeight-headerLines.Length-10)); break;
      case ConsoleKey.DownArrow: selected++; break;
      case ConsoleKey.Backspace: if(input.Length>0) input=input.Substring(0,input.Length-1); break;
      default: if(input.Length<31 && ((k.KeyChar>='0'&&k.KeyChar<='9')||k.KeyChar=='.'||k.KeyChar=='/'||k.KeyChar=='-')) input+=k.KeyChar; break;
     }
    } Thread.Sleep(80);
   }
  } finally { StopArp(); CloseOsDetection(); if(!IsWindows) StopLinuxMouseInput(); Console.CancelKeyPress-=interactiveCancel; if(mdnsCancel!=null) mdnsCancel.Cancel(); if(mdnsTask!=null) { try { mdnsTask.Wait(1500); } catch(AggregateException) {} } ClosePortScan(); if(IsWindows) SetConsoleMode(inputHandle,originalInputMode); StopContinuousPing(true); if(cancel!=null) cancel.Cancel(); RestoreThemeOutput(); Console.CursorVisible=visible; ClearScreen(); if(!IsWindows) Console.Write("\u001b[?1049l"); }
 }
 // Prueft grundlegende Bereichs-, MAC-, Tabellen- und Exportinvarianten ohne interaktive Oberflaeche.
 public static void Test() {
  // Also exercise reflection-loaded JSON dependencies inside the published bundle.
  var jsonCheck=ParsePktAdapterIdentities("[{\"Components\":[{\"Id\":17,\"Properties\":[{\"Name\":\"MAC-Adresse\",\"Value\":\"00-11-22-33-44-55\"}]}]}]");
  if(!jsonCheck.ContainsKey(17) || jsonCheck[17].Macs[0]!="00:11:22:33:44:55") throw new Exception("PktMon JSON dependencies or parsing unavailable.");
  if(typeof(App).Assembly.GetManifestResourceNames().Contains("KubScan.oui.csv") && oui.Count<1000) throw new Exception("Embedded OUI database not loaded.");
  if(Parse("192.168.1.42/24").Length!=254 || IP(Parse("192.168.1.42/24")[0])!="192.168.1.1" || IP(Parse("192.168.1.42/24").Last())!="192.168.1.254") throw new Exception("/24");
  if(Parse("10.0.0.0/31").Length!=2 || Parse("127.0.0.1/32").Length!=1 || Parse("10.0.0.0/16").Length!=65534) throw new Exception("Hostbereich");
  foreach(string s in new[]{"abc","300.1.1.1/24","1.2.3/24","10.0.0.1/33","10.0.0.1/8"}) { bool rejected=false; try { Parse(s); } catch(ArgumentException) { rejected=true; } if(!rejected) throw new Exception(s); }
  if(FormatMac(new byte[]{0,17,34,170,187,255})!="00:11:22:AA:BB:FF") throw new Exception("MAC-Format");
  if(MacAddress("127.0.0.1")!="Nicht verfuegbar (Loopback)") throw new Exception("Loopback-MAC");
  var host=new Host { IP="192.168.1.10", DNS="testhost.example", MAC="00:11:22:AA:BB:FF", Vendor="Testhersteller" };
  if(!HostRow(host,80).Contains(host.MAC) || !HostRow(host,80).Contains(host.DNS) || HostRow(host,29).Length!=29) throw new Exception("Hostliste");
  string row=HostRow(host,100);
  if(row.IndexOf(host.IP)>=row.IndexOf(host.DNS) || row.IndexOf(host.DNS)>=row.IndexOf(host.MAC) || row.IndexOf(host.MAC)>=row.IndexOf(host.Vendor)) throw new Exception("Spaltenreihenfolge");
  if(Vendor("02:11:22:33:44:55")!="Lokal/privat oder Multicast" || Vendor("Nicht verfuegbar")!="Nicht verfuegbar") throw new Exception("OUI-Fallback");
  string previous; bool existed=oui.TryGetValue("001122",out previous); oui["001122"]="Testhersteller";
  if(Vendor("00:11:22:AA:BB:FF")!="Testhersteller") throw new Exception("OUI-Lookup");
  if(existed) oui["001122"]=previous; else oui.Remove("001122");
  Console.WriteLine("OK: OUI-Lookup, Spaltenreihenfolge, MAC und CIDR, Normalisierung, Hostbereiche, /16, /31, /32, ungueltige Eingaben.");
 }
}}
