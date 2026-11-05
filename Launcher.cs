using System;
using System.IO;
namespace KubScan {
 public static class Launcher {
  internal static int[] DefaultPorts => new[]{21,22,23,25,53,80,110,135,139,143,443,445,587,993,995,1433,3306,3389,5432,5900,8080,8443};
  public static int Main(string[] args) {
   int[] ports=DefaultPorts;
   try {
#if PORTABLE_GUI
    if(args.Length==0 && !PortableGui.HasInteractiveParentConsole() && PortableGui.CanLaunch())
     return PortableGui.Run();
    PortableGui.ConnectConsole();
    if(args.Length>0 && args[0]=="--tui") args=args[1..];
#endif
    // Versionsabfragen benoetigen weder OUI-Datenbank noch Benutzereinstellungen.
    if(args.Length==1 && args[0]=="--version") { Console.WriteLine("KubScan "+App.Version); return 0; }
    string data=Environment.OSVersion.Platform==PlatformID.Win32NT?null:Environment.GetEnvironmentVariable("KUBSCAN_DATA_HOME");
    if(!string.IsNullOrEmpty(data)) {
     if(!Path.IsPathRooted(data)) throw new ArgumentException("KUBSCAN_DATA_HOME must be an absolute path.");
     Directory.CreateDirectory(data);
     string localOui=Path.Combine(data,"oui.csv");
     if(!File.Exists(localOui)) {
      string temporary=localOui+"."+Guid.NewGuid().ToString("N")+".tmp";
      try {
       using(var source=App.OpenBundledOui())
       using(var output=File.Create(temporary)) source.CopyTo(output);
       try { File.Move(temporary,localOui); } catch(IOException) { if(!File.Exists(localOui)) throw; }
      } finally { if(File.Exists(temporary)) File.Delete(temporary); }
     }
     App.LoadOui(localOui); App.ConfigureExportDirectory(Path.Combine(data,"exports"));
    } else App.PrepareBundledOui();
    App.InitializeSettings();
    args=App.ConfigureStartupArguments(args);
    var remaining=new System.Collections.Generic.List<string>();
    string subnet=""; bool selfTest=false,version=false;
    for(int i=0;i<args.Length;i++) {
     if(string.Equals(args[i],"-Ports",StringComparison.OrdinalIgnoreCase)) {
      if(++i==args.Length) throw new ArgumentException("-Ports requires a port list.");
      ports=App.ParsePortSelection(args[i]);
     } else if(string.Equals(args[i],"-Subnet",StringComparison.OrdinalIgnoreCase)) {
      if(++i==args.Length) throw new ArgumentException("-Subnet requires a scan range.");
      subnet=args[i];
     } else if(string.Equals(args[i],"-SelfTest",StringComparison.OrdinalIgnoreCase) || args[i]=="--self-test") selfTest=true;
     else if(args[i]=="--version") version=true;
     else remaining.Add(args[i]);
    }
    if(version) { Console.WriteLine("KubScan "+App.Version); return 0; }
    if(selfTest) { App.Test(); return 0; }
    if(remaining.Count>0) {
     if(subnet.Length>0) remaining.Add(subnet);
     return App.RunCommandLine(remaining.ToArray(),ports);
    }
    App.Run(subnet,ports); return 0;
   } catch(Exception error) { Console.Error.WriteLine(error.Message); return 1; }
  }
 }
}
