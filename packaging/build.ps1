$ErrorActionPreference = 'Stop'
Push-Location (Join-Path $PSScriptRoot '..')
try {
    $python = Join-Path (Get-Location) '.venv\Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $python)) {
        $python = (Get-Command python.exe -ErrorAction Stop).Source
    }

    $iscc = (Get-Command ISCC.exe -ErrorAction SilentlyContinue).Source
    if (-not $iscc) {
        $candidates = @(
            (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe'),
            (Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'),
            (Join-Path $env:ProgramFiles 'Inno Setup 6\ISCC.exe')
        )
        $iscc = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    }
    if (-not $iscc) {
        throw 'Inno Setup 6 (ISCC.exe) not found. Install Inno Setup 6 or add ISCC.exe to PATH.'
    }

    $version = (& $python -c "import deeplister; print(deeplister.__version__)").Trim()
    if (-not $version) { throw 'Failed to detect DeepLister version.' }
    Write-Host "Building DeepLister v$version ..."

    # 1. Run PyInstaller with clean PATH (avoid unrelated DLL pollution)
    $priorPath = $env:PATH
    try {
        $env:PATH = "$(Split-Path $python);$env:SystemRoot\System32;$env:SystemRoot"
        & $python -m PyInstaller --noconfirm --clean packaging/deeplister.spec
        if ($LASTEXITCODE -ne 0) { throw 'PyInstaller build failed.' }
    } finally {
        $env:PATH = $priorPath
    }

    $exe = Get-Item -LiteralPath 'dist\DeepLister\DeepLister.exe'

    # Copy documentation alongside the app
    foreach ($doc in @('README.md', 'LICENSE')) {
        Copy-Item -LiteralPath $doc -Destination (Join-Path $exe.DirectoryName $doc) -Force
    }

    # 2. Smoke-test frozen executable with clean system PATH
    $priorPlatform = $env:QT_QPA_PLATFORM
    try {
        $env:QT_QPA_PLATFORM = 'offscreen'
        $env:PATH = "$env:SystemRoot\System32;$env:SystemRoot"
        $smoke = Start-Process -FilePath $exe.FullName -WorkingDirectory $exe.DirectoryName -ArgumentList '--smoke-test' -PassThru -WindowStyle Hidden
    } finally {
        $env:QT_QPA_PLATFORM = $priorPlatform
        $env:PATH = $priorPath
    }
    if (-not $smoke.WaitForExit(30000)) {
        $smoke.Kill()
        throw 'Frozen DeepLister.exe timed out during --smoke-test.'
    }
    if ($smoke.ExitCode -ne 0) {
        throw "Frozen DeepLister.exe failed --smoke-test with exit code $($smoke.ExitCode)."
    }
    Write-Host "Smoke test passed!"

    # 3. Compile Inno Setup Windows Installer
    & $iscc "/DAppVersion=$version" 'packaging\installer.iss'
    if ($LASTEXITCODE -ne 0) { throw 'Inno Setup compilation failed.' }

    $setupExe = Get-Item -LiteralPath "installer\DeepListerSetup-$version.exe"
    $hash = Get-FileHash -Algorithm SHA256 -LiteralPath $setupExe.FullName
    Write-Host "Installer built: $($setupExe.FullName)"
    Write-Host "Size: $([math]::Round($setupExe.Length / 1MB, 2)) MB"
    Write-Host "SHA256: $($hash.Hash)"
} finally {
    Pop-Location
}
