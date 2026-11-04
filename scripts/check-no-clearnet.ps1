# Repository-wide "no clearnet" guard (plan.md 7.1, 10).
#
# Fails the build if socket-bearing APIs appear anywhere outside the allowlist.
# Complements crates/anon-transport/tests/no_clearnet.rs, which runs under
# `cargo test`; this script is for CI and also covers any future non-Rust source.

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $repoRoot) { $repoRoot = (Get-Location).Path }

# APIs that can open a direct connection. A direct socket is a direct socket
# even through an async runtime.
$patterns = @(
    'std::net::TcpStream',
    'std::net::TcpListener',
    'std::net::UdpSocket',
    'std::net::ToSocketAddrs',
    'tokio::net::TcpStream',
    'tokio::net::TcpListener',
    'tokio::net::UdpSocket',
    'async_std::net::TcpStream',
    'async_std::net::TcpListener',
    'async_std::net::UdpSocket',
    'TcpStream::connect',
    'TcpListener::bind',
    'UdpSocket::bind',
    'UdpSocket::connect',
    'hyper::Client::new',
    'reqwest::Client'
)

# Files allowed to mention these. Each entry needs a justification.
$allowed = @(
    'crates/anon-transport/src/arti.rs',          # Arti owns its own sockets.
    'crates/anon-transport/tests/no_clearnet.rs', # Names the patterns it searches for.
    'scripts/check-no-clearnet.ps1'               # This file.
)

Write-Host "Scanning for direct socket usage under $repoRoot ..." -ForegroundColor Cyan

$files = Get-ChildItem -Path (Join-Path $repoRoot 'crates') -Recurse -File -Include *.rs -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch '[\\/]target[\\/]' }

$violations = @()

foreach ($file in $files) {
    $rel = $file.FullName.Substring($repoRoot.Length).TrimStart('\', '/') -replace '\\', '/'
    if ($allowed -contains $rel) { continue }

    $lines = Get-Content -LiteralPath $file.FullName -ErrorAction SilentlyContinue
    if (-not $lines) { continue }

    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        $trimmed = $line.TrimStart()
        # Comments cannot open a socket; skip documentation about the invariant.
        if ($trimmed.StartsWith('//') -or $trimmed.StartsWith('*')) { continue }

        foreach ($p in $patterns) {
            if ($line.Contains($p)) {
                $violations += [pscustomobject]@{
                    File    = $rel
                    Line    = $i + 1
                    Pattern = $p
                }
            }
        }
    }
}

if ($violations.Count -gt 0) {
    Write-Host ""
    Write-Host "FAILED: direct socket usage found outside the transport module." -ForegroundColor Red
    Write-Host "This breaks the no-clearnet-fallback guarantee (plan.md 1.2, 3.4)." -ForegroundColor Red
    Write-Host ""
    $violations | ForEach-Object { Write-Host ("  {0}:{1} uses {2}" -f $_.File, $_.Line, $_.Pattern) }
    Write-Host ""
    exit 1
}

Write-Host "OK: no direct socket usage outside the allowlist." -ForegroundColor Green
exit 0