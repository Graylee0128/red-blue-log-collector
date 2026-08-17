<#
.SYNOPSIS
  End-to-end smoke test against a live docker compose stack.

.DESCRIPTION
  Brings up postgres + collector, waits for /healthz, POSTs the sample
  red/blue events from examples/, and asserts the full pipeline actually
  produces a correlated "hit" with 5000ms latency on /timeline and /analysis.

  Requires Docker Desktop running. Run from the repo root:

    pwsh scripts/smoke-test.ps1

.PARAMETER KeepUp
  Leave the docker compose stack running after the test instead of tearing
  it down.
#>
param(
  [switch]$KeepUp
)

$ErrorActionPreference = "Stop"
$BaseUrl = "http://localhost:8000"
$RepoRoot = Split-Path -Parent $PSScriptRoot

function Fail($message) {
  Write-Host "FAIL: $message" -ForegroundColor Red
  if (-not $KeepUp) {
    docker compose -f "$RepoRoot/docker-compose.yml" down | Out-Null
  }
  exit 1
}

Write-Host "== docker compose up -d --build ==" -ForegroundColor Cyan
docker compose -f "$RepoRoot/docker-compose.yml" up -d --build
if ($LASTEXITCODE -ne 0) { Fail "docker compose up failed" }

Write-Host "== waiting for /healthz ==" -ForegroundColor Cyan
$ready = $false
for ($i = 0; $i -lt 30; $i++) {
  try {
    $health = Invoke-RestMethod -Uri "$BaseUrl/healthz" -Method Get -TimeoutSec 3
    if ($health.status -eq "ok") { $ready = $true; break }
  } catch {}
  Start-Sleep -Seconds 2
}
if (-not $ready) { Fail "/healthz never returned ok within 60s" }
Write-Host "healthz OK" -ForegroundColor Green

Write-Host "== POST examples/red-event.json -> /ingest/red ==" -ForegroundColor Cyan
$redEvent = Get-Content "$RepoRoot/examples/red-event.json" -Raw
$redResp = Invoke-RestMethod -Uri "$BaseUrl/ingest/red" -Method Post -ContentType "application/json" -Body $redEvent
if ($redResp.inserted -ne $true) { Fail "red event was not inserted: $($redResp | ConvertTo-Json -Depth 5)" }
Write-Host "red event inserted: $($redResp.event.event_id)" -ForegroundColor Green

Write-Host "== POST examples/blue-event.json -> /ingest/blue ==" -ForegroundColor Cyan
$blueEvent = Get-Content "$RepoRoot/examples/blue-event.json" -Raw
$blueResp = Invoke-RestMethod -Uri "$BaseUrl/ingest/blue" -Method Post -ContentType "application/json" -Body $blueEvent
if ($blueResp.inserted -ne $true) { Fail "blue event was not inserted: $($blueResp | ConvertTo-Json -Depth 5)" }
Write-Host "blue event inserted: $($blueResp.event.event_id)" -ForegroundColor Green

Write-Host "== GET /timeline ==" -ForegroundColor Cyan
$timeline = Invoke-RestMethod -Uri "$BaseUrl/timeline" -Method Get
if ($timeline.Count -lt 2) { Fail "expected >=2 events on timeline, got $($timeline.Count)" }
Write-Host "timeline has $($timeline.Count) event(s)" -ForegroundColor Green

Write-Host "== GET /analysis ==" -ForegroundColor Cyan
$analysis = Invoke-RestMethod -Uri "$BaseUrl/analysis" -Method Get
Write-Host ($analysis | ConvertTo-Json -Depth 6)

if ($analysis.detected -lt 1) { Fail "expected at least 1 detected hit, got $($analysis.detected)" }
if ($analysis.detection_rate -ne 1) { Fail "expected detection_rate 1.0, got $($analysis.detection_rate)" }
if ($analysis.mttd_p50_ms -ne 5000) { Fail "expected mttd_p50_ms 5000 (5s gap in example events), got $($analysis.mttd_p50_ms)" }

Write-Host "`nALL SMOKE ASSERTIONS PASSED: red action -> blue detection -> correlation -> latency -> hit" -ForegroundColor Green

if (-not $KeepUp) {
  Write-Host "== docker compose down ==" -ForegroundColor Cyan
  docker compose -f "$RepoRoot/docker-compose.yml" down | Out-Null
}
