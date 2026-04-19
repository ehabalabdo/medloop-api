$ErrorActionPreference = "Stop"
Set-Location "C:\Users\Ehab\Desktop\medloop-api"

$files = Get-ChildItem -Recurse -File -Include *.js -Path "src" |
    Where-Object { $_.FullName -notmatch "node_modules" }

$fixed = 0
foreach ($f in $files) {
    $lines = Get-Content $f.FullName
    $out = New-Object System.Collections.Generic.List[string]
    $loggerLine = $null
    $skip = $false
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        # detect a logger import line that landed inside a multi-line import { ... }
        if ($line -match '^import logger from\s+".*utils/logger\.js";\s*$') {
            # If previous non-empty out line ends with `{` or contains `import {` without closing `}`,
            # we likely split a multi-line import — defer logger import to after closing brace.
            $prev = ($out | Where-Object { $_ -match '\S' } | Select-Object -Last 1)
            if ($prev -match '^\s*import\s*\{?\s*$' -or $prev -match 'import\s*\{[^}]*$') {
                $loggerLine = $line
                continue
            }
        }
        $out.Add($line) | Out-Null
        # If we deferred the logger import and we just emitted a line ending with `} from "..."`
        if ($loggerLine -and $line -match '\}\s*from\s+["''][^"'']+["''];?\s*$') {
            $out.Add($loggerLine) | Out-Null
            $loggerLine = $null
        }
    }
    if ($loggerLine) { $out.Add($loggerLine) | Out-Null }

    $newContent = ($out -join "`r`n")
    $orig = [System.IO.File]::ReadAllText($f.FullName)
    if ($newContent -ne $orig.TrimEnd("`r","`n")) {
        [System.IO.File]::WriteAllText($f.FullName, $newContent + "`r`n")
        $fixed++
        Write-Host "  fixed: $($f.FullName.Replace($PWD.Path + '\', ''))"
    }
}
Write-Host "Files fixed: $fixed"
