param(
    [string]$Dotnet = 'dotnet',
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '../dist/portable-win-x64')
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$staging = Join-Path ([IO.Path]::GetTempPath()) ('KubScan-publish-' + [guid]::NewGuid().ToString('N'))
$gui = Join-Path $staging 'gui'
$archive = Join-Path $staging 'gui.zip'
$bundle = Join-Path $staging 'bundle'
New-Item -ItemType Directory -Path $staging | Out-Null

try {
    & $Dotnet publish (Join-Path $repo 'WinUI/KubScan.WinUI.csproj') -c Release -o $gui
    if ($LASTEXITCODE -ne 0) { throw 'WinUI publish failed.' }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $compression = if ([Enum]::IsDefined([IO.Compression.CompressionLevel], 'SmallestSize')) {
        [IO.Compression.CompressionLevel]::SmallestSize
    } else {
        [IO.Compression.CompressionLevel]::Optimal
    }
    [IO.Compression.ZipFile]::CreateFromDirectory($gui, $archive, $compression, $false)
    & $Dotnet publish (Join-Path $repo 'KubScan.csproj') -c Release -r win-x64 -o $bundle "-p:PortableGuiArchive=$archive" -p:PublishTrimmed=false -p:EnableCompressionInSingleFile=true
    if ($LASTEXITCODE -ne 0) { throw 'Portable publish failed.' }
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $bundle 'KubScan.exe') -Destination (Join-Path $OutputDirectory 'KubScan.exe') -Force
}
finally {
    $resolved = (Resolve-Path -LiteralPath $staging).ProviderPath
    if ($resolved -eq [IO.Path]::GetFullPath($staging)) {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
