# Import the local synthetic topology into the configured Neo4j database.
Set-Location $PSScriptRoot
$envFile = Join-Path $PSScriptRoot ".env"
if (-not (Test-Path $envFile)) { throw "Create .env before syncing Neo4j." }
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
$env:PYTHONPATH = "src"
$env:SB_DATA_DIR = "$PSScriptRoot\.sbdata"
.venv\Scripts\python -m switchboard.cli sync-neo4j
