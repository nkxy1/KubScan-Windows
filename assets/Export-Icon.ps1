param(
 [string]$Source=(Join-Path $PSScriptRoot 'Kubscan.png'),
 [string]$Destination=(Join-Path $PSScriptRoot 'Kubscan.ico')
)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Drawing
$sizes=@(16,20,24,32,40,48,64,128,256)
$images=New-Object 'System.Collections.Generic.List[byte[]]'
$original=[Drawing.Image]::FromFile($Source)
try {
 foreach($size in $sizes){
  $bitmap=New-Object Drawing.Bitmap($size,$size,[Drawing.Imaging.PixelFormat]::Format32bppArgb)
  $graphics=[Drawing.Graphics]::FromImage($bitmap)
  $stream=New-Object IO.MemoryStream
  try {
   $graphics.CompositingMode=[Drawing.Drawing2D.CompositingMode]::SourceCopy
   $graphics.InterpolationMode=[Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
   $graphics.PixelOffsetMode=[Drawing.Drawing2D.PixelOffsetMode]::HighQuality
   $graphics.DrawImage($original,[Drawing.Rectangle]::new(0,0,$size,$size))
   $bitmap.Save($stream,[Drawing.Imaging.ImageFormat]::Png)
   $images.Add($stream.ToArray())
   if($size -eq 256){$bitmap.Save((Join-Path $PSScriptRoot 'Kubscan-preview.png'),[Drawing.Imaging.ImageFormat]::Png)}
  } finally {$stream.Dispose(); $graphics.Dispose(); $bitmap.Dispose()}
 }
} finally {$original.Dispose()}
$writer=New-Object IO.BinaryWriter([IO.File]::Create($Destination))
try {
 $writer.Write([uint16]0); $writer.Write([uint16]1); $writer.Write([uint16]$sizes.Count)
 $offset=6+16*$sizes.Count
 for($i=0;$i -lt $sizes.Count;$i++){
  $dimension=if($sizes[$i] -eq 256){0}else{$sizes[$i]}
  $writer.Write([byte]$dimension); $writer.Write([byte]$dimension)
  $writer.Write([byte]0); $writer.Write([byte]0)
  $writer.Write([uint16]1); $writer.Write([uint16]32)
  $writer.Write([uint32]$images[$i].Length); $writer.Write([uint32]$offset)
  $offset+=$images[$i].Length
 }
 foreach($bytes in $images){$writer.Write($bytes)}
} finally {$writer.Dispose()}
Write-Output "ICO: $Destination (16, 20, 24, 32, 40, 48, 64, 128, 256 px)"
