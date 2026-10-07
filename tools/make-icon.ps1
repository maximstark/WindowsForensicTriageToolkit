# =============================================================================
# make-icon.ps1 -- regenerates src/ui/app.ico (the shield + traffic-light mark)
# =============================================================================
# The icon is committed; run this only if the mark changes. Draws each size
# natively (no downscaling blur) and packs PNG frames into one .ico.
# =============================================================================

Add-Type -AssemblyName System.Drawing
$ErrorActionPreference = "Stop"
$out   = Join-Path (Split-Path -Parent $PSScriptRoot) "src\ui\app.ico"
$sizes = 16, 20, 24, 32, 40, 48, 64, 128, 256

function New-Frame([int]$px) {
    $bmp = New-Object System.Drawing.Bitmap $px, $px
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = "AntiAlias"
    $g.PixelOffsetMode = "HighQuality"
    $s = $px / 24.0
    # Shield: same geometry as the XAML logo (24x24 design grid)
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $path.AddLine(12*$s, 1.2*$s, 21*$s, 4.5*$s)
    $path.AddLine(21*$s, 4.5*$s, 21*$s, 11.2*$s)
    $path.AddBezier(21*$s, 11.2*$s, 21*$s, 16.8*$s, 17.2*$s, 21.2*$s, 12*$s, 22.8*$s)
    $path.AddBezier(12*$s, 22.8*$s, 6.8*$s, 21.2*$s, 3*$s, 16.8*$s, 3*$s, 11.2*$s)
    $path.AddLine(3*$s, 11.2*$s, 3*$s, 4.5*$s)
    $path.CloseFigure()
    $g.FillPath((New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 22, 32, 51))), $path)
    $pen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(255, 59, 130, 246)), ([math]::Max(1.0, 1.5 * $s))
    $pen.LineJoin = "Round"
    $g.DrawPath($pen, $path)
    # Lights: bigger at small sizes so they survive 16px
    $d  = if ($px -le 24) { 5.2 } else { 4.2 }
    $gap = if ($px -le 24) { 5.4 } else { 4.9 }
    $colors = @(
        [System.Drawing.Color]::FromArgb(255, 239, 68, 68),
        [System.Drawing.Color]::FromArgb(255, 234, 179, 8),
        [System.Drawing.Color]::FromArgb(255, 34, 197, 94))
    for ($i = 0; $i -lt 3; $i++) {
        $cy = 7.4 + $i * $gap
        $g.FillEllipse((New-Object System.Drawing.SolidBrush $colors[$i]), (12 - $d/2)*$s, ($cy - $d/2)*$s, $d*$s, $d*$s)
    }
    $g.Dispose()
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    return ,$ms.ToArray()
}

$frames = foreach ($px in $sizes) { ,(New-Frame $px) }
$fs = [System.IO.File]::Create($out)
$w = New-Object System.IO.BinaryWriter $fs
$w.Write([uint16]0); $w.Write([uint16]1); $w.Write([uint16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $px = $sizes[$i]; $len = $frames[$i].Length
    $b = if ($px -ge 256) { 0 } else { $px }
    $w.Write([byte]$b); $w.Write([byte]$b); $w.Write([byte]0); $w.Write([byte]0)
    $w.Write([uint16]1); $w.Write([uint16]32); $w.Write([uint32]$len); $w.Write([uint32]$offset)
    $offset += $len
}
foreach ($f in $frames) { $w.Write($f) }
$w.Close()
Write-Host "Wrote $out ($((Get-Item $out).Length) bytes, $($sizes.Count) sizes)"
