<#  collect_endpoint_artifacts.ps1
    Collect Windows passthrough endpoint evidence for TestPulse.

    Outputs a ZIP containing:
      - Wired-AutoConfig Operational log (EVTX)
      - EapHost Operational log (EVTX)
      - System log (EVTX) [optional]
      - netsh lan profiles + selected profile dump
      - ipconfig /all
      - cert store dumps (if enabled)
      - optional EAPOL PCAP (if tshark exists)

    Requires:
      - Admin recommended (for EVTX export + packet capture)
      - Optional: tshark installed (Npcap + Wireshark/tshark)
#>

param(
  [Parameter(Mandatory=$true)]
  [string]$RunId,

  [Parameter(Mandatory=$false)]
  [string]$OutRoot = "C:\TestPulse\runs",

  # Optional: specify a wired profile name to dump
  [Parameter(Mandatory=$false)]
  [string]$LanProfileName = "",

  # Collect System log too (bigger, but useful)
  [Parameter(Mandatory=$false)]
  [switch]$IncludeSystemLog,

  # Collect certificate store output (useful for EAP-TLS / PEAP-EAP-TLS)
  [Parameter(Mandatory=$false)]
  [switch]$IncludeCerts,

  # Attempt EAPOL packet capture with tshark (if installed)
  [Parameter(Mandatory=$false)]
  [switch]$CaptureEapol,

  [Parameter(Mandatory=$false)]
  [int]$CaptureSeconds = 90,

  # Optional: override capture interface name for tshark
  [Parameter(Mandatory=$false)]
  [string]$CaptureInterface = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Ensure-Dir($p) {
  if (!(Test-Path $p)) { New-Item -ItemType Directory -Path $p | Out-Null }
}

function Write-Text($path, $content) {
  $content | Out-File -FilePath $path -Encoding UTF8
}

function Try-Run($label, [scriptblock]$sb) {
  try {
    & $sb
  } catch {
    $msg = "[WARN] $label failed: $($_.Exception.Message)"
    $msg | Out-Host
    $msg | Out-File -FilePath $Global:warnPath -Append -Encoding UTF8
  }
}

$ts = (Get-Date).ToString("yyyyMMdd_HHmmss")
$runDir = Join-Path $OutRoot $RunId
$artDir = Join-Path $runDir "artifacts\endpoint_windows"
Ensure-Dir $artDir

$Global:warnPath = Join-Path $artDir "collector_warnings.txt"
Write-Text $Global:warnPath "Warnings for RunId=$RunId at $ts`r`n"

# Metadata
$meta = @{
  run_id = $RunId
  collected_at_local = (Get-Date).ToString("o")
  computer = $env:COMPUTERNAME
  user = $env:USERNAME
  out_dir = $artDir
}
($meta | ConvertTo-Json -Depth 6) | Out-File (Join-Path $artDir "endpoint_metadata.json") -Encoding UTF8

# --- Event logs (EVTX) ---
# Wired AutoConfig Operational log
Try-Run "Export Wired-AutoConfig/Operational" {
  $dst = Join-Path $artDir "wired_autoconfig_operational.evtx"
  wevtutil epl "Microsoft-Windows-Wired-AutoConfig/Operational" $dst
}

# EapHost Operational log (often contains useful EAP errors)
Try-Run "Export EapHost/Operational" {
  $dst = Join-Path $artDir "eaphost_operational.evtx"
  wevtutil epl "Microsoft-Windows-EapHost/Operational" $dst
}

# Optional System log (driver/link flaps, NIC resets)
if ($IncludeSystemLog) {
  Try-Run "Export System log" {
    $dst = Join-Path $artDir "system.evtx"
    wevtutil epl "System" $dst
  }
}

# --- Wired 802.1X profile info ---
Try-Run "netsh lan show profiles" {
  $out = netsh lan show profiles
  Write-Text (Join-Path $artDir "netsh_lan_show_profiles.txt") $out
}

# Choose a profile name if not provided (best-effort: first profile found)
if ([string]::IsNullOrWhiteSpace($LanProfileName)) {
  Try-Run "Detect LAN profile name" {
    $profilesTxt = Get-Content (Join-Path $artDir "netsh_lan_show_profiles.txt") -ErrorAction Stop
    # Typical line: "All User Profile     : <name>"
    $match = $profilesTxt | Select-String -Pattern "All User Profile\s*:\s*(.+)$" | Select-Object -First 1
    if ($match) {
      $LanProfileName = $match.Matches[0].Groups[1].Value.Trim()
    }
  }
}

if (![string]::IsNullOrWhiteSpace($LanProfileName)) {
  Try-Run "netsh lan show profile" {
    $out = netsh lan show profile name="$LanProfileName"
    $safeName = ($LanProfileName -replace '[\\/:*?"<>| ]','_')
    Write-Text (Join-Path $artDir "netsh_lan_profile_${safeName}.txt") $out
    Write-Text (Join-Path $artDir "netsh_lan_profile_selected.txt") $LanProfileName
  }
} else {
  "No LAN profile detected/provided." | Out-File -FilePath $Global:warnPath -Append -Encoding UTF8
}

# --- Network context ---
Try-Run "ipconfig /all" {
  $out = ipconfig /all
  Write-Text (Join-Path $artDir "ipconfig_all.txt") $out
}

Try-Run "route print" {
  $out = route print
  Write-Text (Join-Path $artDir "route_print.txt") $out
}

Try-Run "arp -a" {
  $out = arp -a
  Write-Text (Join-Path $artDir "arp_a.txt") $out
}

# --- Certificates (optional; helpful for EAP-TLS/PEAP-EAP-TLS) ---
if ($IncludeCerts) {
  Try-Run "certutil user MY" {
    $out = certutil -store -user my
    Write-Text (Join-Path $artDir "cert_store_user_my.txt") $out
  }
  Try-Run "certutil localmachine MY" {
    $out = certutil -store my
    Write-Text (Join-Path $artDir "cert_store_machine_my.txt") $out
  }
  Try-Run "certutil root" {
    $out = certutil -store root
    Write-Text (Join-Path $artDir "cert_store_root.txt") $out
  }
}

# --- Optional EAPOL capture (tshark) ---
if ($CaptureEapol) {
  Try-Run "tshark EAPOL capture" {
    $tshark = (Get-Command tshark.exe -ErrorAction Stop).Source
    $pcapDir = Join-Path $artDir "pcap"
    Ensure-Dir $pcapDir
    $pcapPath = Join-Path $pcapDir "eapol_endpoint.pcapng"

    # Decide capture interface
    $iface = $CaptureInterface
    if ([string]::IsNullOrWhiteSpace($iface)) {
      # Best effort: pick first "Ethernet" interface from tshark -D output
      $iflist = & $tshark -D
      Write-Text (Join-Path $artDir "tshark_interfaces.txt") $iflist
      $line = ($iflist | Select-String -Pattern "Ethernet" | Select-Object -First 1)
      if ($line) {
        # tshark -D lines look like "1. \Device\NPF_{...} (Ethernet)"
        $iface = $line.Line.Split(".")[0].Trim()
      } else {
        $iface = "1"
      }
    }

    # Capture EAPOL ethertype only; duration-bounded
    & $tshark -i $iface -f "ether proto 0x888e" -a "duration:$CaptureSeconds" -w $pcapPath | Out-Null
  }
}

# --- Package into a ZIP for scp ---
$zipPath = Join-Path $runDir ("endpoint_windows_{0}.zip" -f $RunId)
Try-Run "Compress-Archive" {
  if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
  Compress-Archive -Path (Join-Path $artDir "*") -DestinationPath $zipPath -Force
}

Write-Host "[OK] Collected endpoint artifacts for RunId=$RunId"
Write-Host "[OK] Output ZIP: $zipPath"