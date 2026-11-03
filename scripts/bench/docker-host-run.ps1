# Copyright (c) 2026 Suryansh Deshwal
# Licensed under the Apache License, Version 2.0
#
# One-shot VX6 IPsec validation on Windows with Docker Desktop (Linux
# containers, WSL2 backend). Needs only Docker Desktop running; Git, Go
# and WSL tools are not required because everything runs in containers.
#
#   powershell -ExecutionPolicy Bypass -File .\docker-host-run.ps1
#
# Steps:
#   1. download the branch under test as a zip
#   2. check the Docker VM kernel for IPv6 and XFRM ESP/AES-GCM
#   3. go test internal/ipsec + internal/transport (Linux, IPv6 loopback)
#   4. #51 baseline benchmark (split selectors) + pinned-selector negative control
#   5. routed IPv6 capture suite tests/ipsec-e2e/run.sh (if the kernel supports it)
#   6. write Desktop\vx6-docker-results-<time>.zip (logs + transcript)
#   7. remove every container, network, image, volume path and temp file it created
#      (images that existed before the run are kept)
#
# Host networking is never touched. Windows PowerShell 5.1 compatible.

param(
  [string]$Repo = "dailker/vx6",
  [string]$Branch = "claude/compassionate-babbage-qjp4bm",
  [int]$Repeat = 5,
  [int]$Duration = 10,
  [switch]$InstallDocker
)

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"
$Stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$Work = Join-Path $env:TEMP "vx6-docker-run-$Stamp"
$Results = Join-Path $Work "results"
$BenchImage = "vx6-bench:$Stamp"
$E2EImage = "vx6-ipsec-e2e:local"
$Label = "vx6-docker-host-run=$Stamp"
$VmDir = "/tmp/vx6-run-$Stamp"          # path inside the Docker VM, shared by sibling containers
$Desktop = [Environment]::GetFolderPath("Desktop")
if (-not (Test-Path $Desktop)) { $Desktop = $env:USERPROFILE }
$Archive = Join-Path $Desktop "vx6-docker-results-$Stamp.zip"

New-Item -ItemType Directory -Force -Path $Results | Out-Null
Start-Transcript -Path (Join-Path $Results "transcript.txt") | Out-Null

function Say($msg) { Write-Host "`n>> $msg" -ForegroundColor Magenta }
function Note($msg) { Write-Host "   $msg" }

# ---------------------------------------------------------------- find / start Docker
function Find-Docker {
  if (Get-Command docker -ErrorAction SilentlyContinue) { return $true }
  foreach ($dir in @("$env:ProgramFiles\Docker\Docker\resources\bin", "$env:LOCALAPPDATA\Programs\Docker\Docker\resources\bin")) {
    if (Test-Path (Join-Path $dir "docker.exe")) { $env:Path = "$dir;$env:Path"; return $true }
  }
  return $false
}
$script:HaveDocker = Find-Docker
if (-not $script:HaveDocker -and $InstallDocker) {
  Say "Installing Docker Desktop with winget (needs admin; a restart may be required)"
  winget install -e --id Docker.DockerDesktop --accept-package-agreements --accept-source-agreements
  $script:HaveDocker = Find-Docker
}
if (-not $script:HaveDocker) {
  try { Stop-Transcript | Out-Null } catch {}
  Remove-Item -Recurse -Force $Work -ErrorAction SilentlyContinue
  Write-Host ""
  Write-Host "Docker Desktop is not installed on this PC." -ForegroundColor Yellow
  Write-Host "  1. Install it: https://docs.docker.com/desktop/setup/install/windows-install/"
  Write-Host "     or run this script again with -InstallDocker (uses winget, needs admin)."
  Write-Host "  2. Use the WSL 2 backend (the default), reboot if the installer asks, start Docker Desktop once."
  Write-Host "  3. Run: powershell -ExecutionPolicy Bypass -File .\docker-host-run.ps1"
  exit 2
}
docker info 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) {
  $dd = Join-Path $env:ProgramFiles "Docker\Docker\Docker Desktop.exe"
  if (Test-Path $dd) {
    Say "Starting Docker Desktop (waiting up to 3 minutes)"
    Start-Process $dd | Out-Null
    for ($i = 0; $i -lt 90; $i++) {
      Start-Sleep -Seconds 2
      docker info 2>$null | Out-Null
      if ($LASTEXITCODE -eq 0) { break }
    }
  }
}

$preImages = @(docker images -q 2>$null | Sort-Object -Unique)

function Cleanup {
  Say "Cleaning up"
  $ids = docker ps -aq --filter "label=$Label" 2>$null
  if ($ids) { docker rm -f $ids 2>$null | Out-Null }
  $ids = docker ps -aq --filter "name=vx6-e2e-" 2>$null
  if ($ids) { docker rm -f $ids 2>$null | Out-Null }
  $nets = docker network ls -q --filter "name=vx6-e2e-" 2>$null
  if ($nets) { docker network rm $nets 2>$null | Out-Null }
  # remove the shared scratch directory inside the Docker VM
  if (docker images -q $BenchImage 2>$null) {
    docker run --rm -v "/tmp:/vmtmp" $BenchImage rm -rf "/vmtmp/vx6-run-$Stamp" 2>$null | Out-Null
  }
  foreach ($img in @($BenchImage, $E2EImage, "golang:1.24-bookworm", "docker:27-cli", "ubuntu:22.04")) {
    $id = docker images -q $img 2>$null
    if ($id -and -not ($preImages -contains $id)) {
      docker rmi -f $img 2>$null | Out-Null
      Note "removed image $img"
    }
  }
  docker image prune -f --filter "label=$Label" 2>$null | Out-Null
  try { Stop-Transcript | Out-Null } catch {}
  if (Test-Path $Results) {
    Compress-Archive -Path (Join-Path $Results "*") -DestinationPath $Archive -Force
    Write-Host "   results: $Archive" -ForegroundColor Green
  }
  Remove-Item -Recurse -Force $Work -ErrorAction SilentlyContinue
  Note "temporary files removed"
}

try {
  Say "Preflight"
  docker info --format "{{.OSType}}" 2>$null | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "Docker Desktop is not running. Start it (Linux containers mode) and run this again." }
  $osType = docker info --format "{{.OSType}}"
  if ($osType -ne "linux") { throw "Docker is in Windows-containers mode. Right-click the Docker tray icon > Switch to Linux containers." }
  @(
    "host_os=$([Environment]::OSVersion.VersionString)",
    "docker_server=$(docker version --format '{{.Server.Version}} {{.Server.Os}}/{{.Server.Arch}}')",
    "docker_kernel=$(docker info --format '{{.KernelVersion}}')",
    "docker_cpus=$(docker info --format '{{.NCPU}}') docker_mem=$(docker info --format '{{.MemTotal}}')",
    "repo=$Repo branch=$Branch"
  ) | Tee-Object -FilePath (Join-Path $Results "host.txt")

  Say "Downloading $Repo@$Branch"
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
  $zip = Join-Path $Work "src.zip"
  Invoke-WebRequest -UseBasicParsing -Uri "https://codeload.github.com/$Repo/zip/refs/heads/$Branch" -OutFile $zip
  Expand-Archive -Path $zip -DestinationPath (Join-Path $Work "src") -Force
  $SrcDir = (Get-ChildItem (Join-Path $Work "src") -Directory | Select-Object -First 1).FullName
  Note "source: $SrcDir"

  Say "Building the Linux test image"
  $ctx = Join-Path $Work "ctx"
  New-Item -ItemType Directory -Force -Path $ctx | Out-Null
  @'
FROM docker:27-cli AS cli
FROM golang:1.24-bookworm
COPY --from=cli /usr/local/bin/docker /usr/local/bin/docker
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      iproute2 strongswan-charon strongswan-swanctl strongswan-pki \
      libstrongswan-standard-plugins libstrongswan-extra-plugins libcharon-extra-plugins \
      iperf3 tcpdump python3 bc procps psmisc util-linux kmod binutils >/dev/null \
 && rm -rf /var/lib/apt/lists/*
'@ | Set-Content -Encoding Ascii -Path (Join-Path $ctx "Dockerfile")
  docker build -q --label $Label -t $BenchImage $ctx | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "docker build failed" }

  # Each step is written to a small LF-terminated script under results\steps
  # and executed from there. That avoids Windows PowerShell's quoting of native
  # arguments, and the steps are kept with the logs.
  $Steps = Join-Path $Results "steps"
  New-Item -ItemType Directory -Force -Path $Steps | Out-Null
  $script:stepNo = 0
  function Step([string]$body) {
    $script:stepNo++
    $name = "step$($script:stepNo).sh"
    $text = "set -u`nVMDIR='$VmDir'`n" + $body.Replace("`r`n", "`n")
    [IO.File]::WriteAllText((Join-Path $Steps $name), $text)
    return "/results/steps/$name"
  }
  # Run a step in a privileged container (network namespaces, XFRM, charon).
  function RunPriv([string]$body) {
    $f = Step $body
    docker run --rm --privileged --label $Label -v "${VmDir}:${VmDir}" -v "${Results}:/results" -w "$VmDir/vx6" $BenchImage bash $f | Out-Host
    return $LASTEXITCODE
  }

  # Copy the source into a Docker-VM path that sibling containers can also mount.
  $f = Step @'
mkdir -p "$VMDIR" && rm -rf "$VMDIR/vx6" && cp -r /src "$VMDIR/vx6" || exit 1
cd "$VMDIR/vx6"
sed -i 's/\r$//' scripts/bench/*.sh scripts/bench/*.py tests/ipsec-e2e/*.sh tests/ipsec-e2e/*.conf 2>/dev/null
chmod +x scripts/bench/*.sh scripts/bench/*.py tests/ipsec-e2e/*.sh
'@
  docker run --rm --label $Label -v "${SrcDir}:/src:ro" -v "${VmDir}:${VmDir}" -v "${Results}:/results" $BenchImage bash $f | Out-Host
  if ($LASTEXITCODE -ne 0) { throw "could not stage the source inside the Docker VM" }

  Say "Kernel capability check (inside the Docker VM)"
  $null = RunPriv @'
ok6=no; okx=no
[ -d /proc/sys/net/ipv6 ] && ok6=yes
ip netns add vx6chk && ip -n vx6chk link add d0 type veth peer name d1 && ip -n vx6chk link set d0 up
if [ $ok6 = yes ] && ip -n vx6chk -6 addr add fd00::1/64 dev d0 nodad 2>/dev/null; then
  K=0x$(od -An -tx1 -N20 /dev/urandom | tr -d " \n")
  ip -n vx6chk xfrm state add src fd00::1 dst fd00::2 proto esp spi 0x100 mode tunnel aead "rfc4106(gcm(aes))" $K 128 2>/results/xfrm-error.txt && okx=yes
fi
ip netns del vx6chk
echo "ipv6=$ok6 xfrm_esp_gcm=$okx" | tee /results/kernel-capabilities.txt
'@
  $caps = Get-Content (Join-Path $Results "kernel-capabilities.txt") -ErrorAction SilentlyContinue
  Note "kernel: $caps"
  $full = ($caps -match "ipv6=yes xfrm_esp_gcm=yes")
  if ($full) { $Family = 6; $Dataplane = "xfrm"; Note "using the target configuration: IPv6 + kernel XFRM" }
  else { $Family = 4; $Dataplane = "libipsec"; Note "kernel lacks IPv6 or XFRM ESP/GCM: using the IPv4/libipsec fallback" }

  Say "Unit tests: internal/ipsec, internal/transport"
  $rc = RunPriv @'
sysctl -qw net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.lo.disable_ipv6=0 2>/dev/null
go test ./internal/ipsec ./internal/transport -count=1 -v > /results/go-test.txt 2>&1; s=$?
grep -E '^(--- |ok|FAIL)' /results/go-test.txt
exit $s
'@
  if ($rc -ne 0) { Note "go test reported failures (see go-test.txt)" }

  Say "Baseline benchmark (#51): FAMILY=$Family DATAPLANE=$Dataplane REPEAT=$Repeat DURATION=${Duration}s (takes ~10 min)"
  $rc = RunPriv "FAMILY=$Family DATAPLANE=$Dataplane REPEAT=$Repeat DURATION=$Duration OUT=/results/bench-split bash scripts/bench/ipsec-baseline.sh"
  if ($rc -ne 0) { Note "baseline run failed (see bench-split/run.log)" }

  Say "Negative control: pinned selectors from 4e26ace (ephemeral-port dials expected to fail)"
  $null = RunPriv "FAMILY=$Family DATAPLANE=$Dataplane SELECTORS=pinned REPEAT=1 DURATION=2 OUT=/results/bench-pinned timeout 900 bash scripts/bench/ipsec-baseline.sh > /results/bench-pinned.log 2>&1; grep -h errors /results/bench-pinned/rr_esp_small_1.json"

  Say "Routed IPv6 capture suite (tests/ipsec-e2e/run.sh)"
  if ($full) {
    # Runs in a helper container that drives the Docker engine through its socket.
    # TMPDIR is a Docker-VM path, so the peer containers can bind-mount the same files.
    $f = Step @'
export TMPDIR="$VMDIR"
cd "$VMDIR/vx6" || exit 1
VX6_E2E_RESULTS_DIR="$VMDIR/e2e" bash tests/ipsec-e2e/run.sh > /results/e2e.log 2>&1; s=$?
cp -r "$VMDIR/e2e" /results/e2e 2>/dev/null
echo "e2e_exit=$s" | tee -a /results/e2e.log
tail -25 /results/e2e.log
exit $s
'@
    docker run --rm --label $Label -v "//var/run/docker.sock:/var/run/docker.sock" -v "${VmDir}:${VmDir}" -v "${Results}:/results" $BenchImage bash $f | Out-Host
    if ($LASTEXITCODE -ne 0) { Note "e2e suite FAILED (see e2e.log)" } else { Note "e2e suite passed" }
  } else {
    Note "skipped: the e2e suite needs IPv6 + kernel XFRM in the Docker VM"
  }

  Say "Summary"
  Get-Content (Join-Path $Results "bench-split\summary.md") -ErrorAction SilentlyContinue
}
catch {
  Write-Host "`nERROR: $_" -ForegroundColor Red
  "$_" | Out-File -Append (Join-Path $Results "error.txt")
}
finally {
  Cleanup
  Write-Host "`nUpload this file back to Claude: $Archive" -ForegroundColor Green
}
