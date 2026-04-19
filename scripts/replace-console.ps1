$ErrorActionPreference = "Stop"
Set-Location "C:\Users\Ehab\Desktop\medloop-api"
$files = Get-ChildItem -Recurse -File -Include *.js -Path "src" |
    Where-Object { $_.FullName -notmatch "node_modules" -and $_.Name -notin @("logger.js","env.js","app.js") }

$changed = 0
foreach ($f in $files) {
    $content = Get-Content $f.FullName -Raw
    $orig = $content
    if ($content -notmatch 'console\.(log|error|warn|info|debug)') { continue }

    if ($content -notmatch 'utils/logger\.js') {
        $rel = $f.FullName.Replace($PWD.Path + "\src\", "")
        $depth = $rel.Split("\").Length - 1
        $prefix = ("../" * $depth) + "utils/logger.js"
        $importLine = "import logger from `"$prefix`";`r`n"
        # insert after last existing import line
        if ($content -match '(?ms)\A(?<imp>(?:import [^\n]+\r?\n)+)') {
            $content = $content -replace '(?ms)\A((?:import [^\n]+\r?\n)+)', "`$1$importLine"
        } else {
            $content = $importLine + $content
        }
    }

    $content = $content -replace 'console\.error\(', 'logger.error('
    $content = $content -replace 'console\.warn\(',  'logger.warn('
    $content = $content -replace 'console\.log\(',   'logger.info('
    $content = $content -replace 'console\.info\(',  'logger.info('
    $content = $content -replace 'console\.debug\(', 'logger.debug('

    if ($content -ne $orig) {
        Set-Content -Path $f.FullName -Value $content -NoNewline -Encoding UTF8
        $changed++
        Write-Host "  patched: $($f.Name)"
    }
}
Write-Host "Files changed: $changed"
