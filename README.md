<p align="center">
  <img src="assets/Kubscan.png" width="108" alt="KubScan application icon">
</p>

<h1 align="center">KubScan for Windows</h1>
<p align="center">Find devices, discover local services, and monitor ARP requests.</p>
<p align="center">100% VibeCoded with Codex</p>

<p align="center"><strong>English</strong> · <a href="README.de.md">Deutsch</a></p>

<p align="center"><a href="https://github.com/nkxy1/KubScan-Windows/releases/latest"><strong>Download KubScan.exe</strong></a></p>

## Quick start

1. Download the portable `KubScan.exe` from the latest release.
2. Double-click the EXE to open the **graphical interface**. From PowerShell or Command Prompt, run it without arguments or with `--tui` to open the **terminal interface** in the same window.
3. Select **IP** and enter your network range, such as `192.168.1.0/24`. Press **Enter** or **F2** to start. In the GUI, you can also click the start button.

The first GUI launch of each new version shows an extraction progress bar with a percentage. You can cancel and try again later. Subsequent launches reuse the extracted files.

## Graphical interface

![KubScan GUI showing the IP range, mode selector, and details pane](assets/screenshots/gui.jpg)

### Find devices by IP

Enter a subnet such as `192.168.1.0/24`, a range such as `192.168.1.10-25`, or a single IPv4 address. If you enter a single address, the GUI asks for a subnet mask. Choose `/32` to check just that device. Use the arrow next to the input field to see recently or frequently used ranges.

The results show each device's IP address, resolved name, MAC address, and vendor when available. To scan repeatedly, enable continuous scanning with the circular arrow or **F3**, then start the scan. KubScan highlights changes such as devices that appear or stop responding. Press **F9** to stop the scan.

### Discover mDNS services

Select **mDNS** to find services advertised on the local network. KubScan shows the service name, type, host, address, and port when the service provides them. Select an entry to see its details. Press **F2** to run the search again or stop it while it is running.

### Monitor ARP requests

Run KubScan **as administrator** for this mode. Select **ARP**, then choose a network adapter or capture on all adapters. The table shows the time, adapter, sender IP, sender MAC, and target IP for each observed request. Press **F2** to start or stop capturing. Use the reset option under **⋯** to clear the list and start fresh. Capture requires a version of Windows with PktMon streaming support.

### View, check, and save results

- **Filter and sort.** Click the magnifying glass or press **F7** to open the search. Click a column header to sort the list, then click it again to reverse the order.
- **View details and copy values.** Select a result to see its details. Use the arrow in the details pane to move it to the right of or below the table. Right-click a cell to copy its value.
- **Check ports.** Right-click an IP result to run a full TCP port scan, a manual TCP port scan, or a UDP port scan. Manual port selection accepts lists and ranges such as `22,80,443,8000-8010`.
- **Check availability and estimate the operating system.** Continuous ping shows repeated replies and response times. OS detection estimates the operating system from the available clues. Use the context menu to open detected connections such as SSH, RDP, or web interfaces.
- **Export results.** Use the download icon to save IP and mDNS results as CSV or plain text.
- **Open help and change settings.** Press **F1** for help. Use **⋯** to change the language or theme. In IP mode, the same menu lets you update the OUI database that maps MAC address prefixes to vendors.

## Terminal interface (TUI)

![KubScan TUI showing an example network, CIDR reference, and function keys](assets/screenshots/tui.png)

```powershell
.\KubScan.exe --tui
```

Enter a subnet or IP range at the top. The menu bar at the bottom shows the actions for the current mode. Use Up and Down to select a result and Left and Right to choose the sort column. Page Up and Page Down move one page at a time. Press **Space** to open details or **C** to copy the value in the selected column of the IP or mDNS list.

| Key | Action |
| --- | --- |
| **F1** | Open help for the current mode. In small windows, scroll with the arrow keys or Page Up and Page Down. |
| **F2** | Start an IP scan, repeat mDNS discovery, or start or resume ARP capture. |
| **F3** | Start or stop continuous scanning in IP mode. Start a new capture in ARP mode. |
| **F4** | Open continuous ping for the selected host in IP mode. Select a network adapter in ARP mode. |
| **F5 / F6** | Export IP results as CSV or TXT. |
| **F7** | Search the current view. Press **Enter** to apply the filter. |
| **F8** | Update the OUI vendor database in IP mode. |
| **F9 / Esc** | Stop the current action. **Esc** first closes open details or clears the active filter. |
| **M / A** | Switch between IP and mDNS, or between IP and ARP, respectively. |
| **S / P / U / O** | Run a full TCP scan, a manual TCP scan, a UDP scan, or OS detection for the selected IP host, respectively. |
| **T / L** | Choose a color theme or switch between German and English. |
| **F10** | Exit KubScan and return to the shell prompt. |

## Automated scans

Use `scan` to run KubScan from scripts. By default, results appear in the terminal. Use `-csv` and `-txt` to write files, `-OutputPath` to set the destination folder, and `-Ports` to specify which TCP ports to check.

```powershell
.\KubScan.exe scan 127.0.0.1/32
.\KubScan.exe scan 192.168.1.0/24 -csv -txt -OutputPath .\Scanberichte -Ports "22,80,443"
```
