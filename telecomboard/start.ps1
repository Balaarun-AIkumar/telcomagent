# One-click local start (Windows PowerShell): installs if needed, seeds data if needed, opens the UI.
param([switch]$Offline)
Set-Location $PSScriptRoot
# Load optional local secrets/settings from .env without overriding values already
# supplied by the shell. Keep .env out of source control; see .env.example.
$envFile = Join-Path $PSScriptRoot ".env"
if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith("#") -and $line.Contains("=")) {
            $parts = $line -split "=", 2
            $name = $parts[0].Trim()
            $value = $parts[1].Trim()
            if ($name -match '^[A-Za-z_][A-Za-z0-9_]*$' -and
                [string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable($name, "Process"))) {
                if ($value.Length -ge 2 -and
                    (($value.StartsWith('"') -and $value.EndsWith('"')) -or
                     ($value.StartsWith("'") -and $value.EndsWith("'")))) {
                    $value = $value.Substring(1, $value.Length - 2)
                }
                [Environment]::SetEnvironmentVariable($name, $value, "Process")
            }
        }
    }
}
if (-not (Test-Path .venv)) {
    uv venv .venv
    uv pip install --python .venv -e ".[dev]"
}
$env:SB_DEV_ENDPOINTS = "1"
$env:PYTHONPATH = "src"
$env:SB_DATA_DIR = "$PSScriptRoot\.sbdata"
Start-Job { Start-Sleep 4; Start-Process "http://127.0.0.1:8000/" } | Out-Null
if ($Offline) {
    .venv\Scripts\python -W ignore -m switchboard.cli --offline --demo serve gateway --port 8000
} else {
    .venv\Scripts\python -W ignore -m switchboard.cli serve gateway --port 8000
}
