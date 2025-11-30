# Generate-Logo.ps1
# Creates Authentik-style logo for Windows Credential Provider
# Generates ICO file with multiple sizes

param(
    [string]$OutputPath = ".\authentik.ico"
)

Add-Type -AssemblyName System.Drawing

# Create bitmaps at various sizes
$sizes = @(16, 24, 32, 48, 64, 128, 256)

# Authentik brand colors
$primaryColor = [System.Drawing.Color]::FromArgb(253, 75, 45)    # #FD4B2D - Authentik coral
$secondaryColor = [System.Drawing.Color]::FromArgb(255, 107, 74) # #FF6B4A - lighter coral
$white = [System.Drawing.Color]::White

function Draw-AuthentikLogo {
    param(
        [System.Drawing.Graphics]$g,
        [int]$size
    )
    
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    
    $center = $size / 2
    $radius = ($size / 2) - 2
    
    # Create gradient brush for background
    $rect = New-Object System.Drawing.Rectangle(0, 0, $size, $size)
    $gradientBrush = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
        $rect,
        $secondaryColor,
        $primaryColor,
        [System.Drawing.Drawing2D.LinearGradientMode]::ForwardDiagonal
    )
    
    # Draw background circle
    $g.FillEllipse($gradientBrush, 2, 2, $size - 4, $size - 4)
    
    # Calculate scale factor
    $scale = $size / 256.0
    
    # White brush for the "A" shape
    $whiteBrush = New-Object System.Drawing.SolidBrush($white)
    
    # Draw simplified "A" shape
    $aHeight = $size * 0.5
    $aWidth = $size * 0.4
    $aTop = $center - $aHeight * 0.55
    $aBottom = $center + $aHeight * 0.35
    
    # Triangle points for "A"
    $aPoints = @(
        (New-Object System.Drawing.PointF($center, $aTop)),                              # Top
        (New-Object System.Drawing.PointF($center + $aWidth/2, $aBottom)),              # Bottom right
        (New-Object System.Drawing.PointF($center + $aWidth/4, $aBottom)),              # Inner right
        (New-Object System.Drawing.PointF($center + $aWidth/8, $center + $aHeight*0.1)), # Crossbar right
        (New-Object System.Drawing.PointF($center - $aWidth/8, $center + $aHeight*0.1)), # Crossbar left
        (New-Object System.Drawing.PointF($center - $aWidth/4, $aBottom)),              # Inner left
        (New-Object System.Drawing.PointF($center - $aWidth/2, $aBottom))               # Bottom left
    )
    
    $g.FillPolygon($whiteBrush, $aPoints)
    
    # Draw inner triangle (the hole in A) with gradient color
    $holeSize = $aHeight * 0.2
    $holeY = $center - $aHeight * 0.05
    $holePoints = @(
        (New-Object System.Drawing.PointF($center, $holeY - $holeSize)),
        (New-Object System.Drawing.PointF($center + $holeSize * 0.7, $holeY + $holeSize * 0.5)),
        (New-Object System.Drawing.PointF($center - $holeSize * 0.7, $holeY + $holeSize * 0.5))
    )
    
    $g.FillPolygon($gradientBrush, $holePoints)
    
    # Draw key symbol below "A"
    $keyY = $center + $aHeight * 0.45
    $keyRadius = $size * 0.06
    
    # Key head (circle)
    $g.FillEllipse($whiteBrush, $center - $keyRadius, $keyY - $keyRadius, $keyRadius * 2, $keyRadius * 2)
    
    # Key hole
    $holeRadius = $keyRadius * 0.5
    $g.FillEllipse($gradientBrush, $center - $holeRadius, $keyY - $holeRadius, $holeRadius * 2, $holeRadius * 2)
    
    # Key shaft
    $shaftWidth = $size * 0.03
    $shaftHeight = $size * 0.1
    $g.FillRectangle($whiteBrush, $center - $shaftWidth/2, $keyY + $keyRadius, $shaftWidth, $shaftHeight)
    
    # Key teeth
    $toothWidth = $size * 0.025
    $toothHeight = $size * 0.015
    $g.FillRectangle($whiteBrush, $center + $shaftWidth/2, $keyY + $keyRadius + $shaftHeight * 0.3, $toothWidth, $toothHeight)
    $g.FillRectangle($whiteBrush, $center + $shaftWidth/2, $keyY + $keyRadius + $shaftHeight * 0.6, $toothWidth * 0.8, $toothHeight)
    
    # Cleanup
    $gradientBrush.Dispose()
    $whiteBrush.Dispose()
}

Write-Host "Generating Authentik-style logo..." -ForegroundColor Cyan

# Create temporary bitmaps
$bitmaps = @()
foreach ($size in $sizes) {
    $bitmap = New-Object System.Drawing.Bitmap($size, $size)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    
    Draw-AuthentikLogo -g $graphics -size $size
    
    $graphics.Dispose()
    $bitmaps += $bitmap
    
    Write-Host "  Created ${size}x${size} bitmap" -ForegroundColor Gray
}

# Save as PNG for preview
$previewPath = [System.IO.Path]::ChangeExtension($OutputPath, ".png")
$bitmaps[-1].Save($previewPath, [System.Drawing.Imaging.ImageFormat]::Png)
Write-Host "Saved preview: $previewPath" -ForegroundColor Green

# Create ICO file
# ICO format: 
# - 6 byte header
# - 16 bytes per image entry
# - Image data

$ms = New-Object System.IO.MemoryStream

# Write ICO header
$writer = New-Object System.IO.BinaryWriter($ms)
$writer.Write([int16]0)        # Reserved, must be 0
$writer.Write([int16]1)        # Type: 1 = ICO
$writer.Write([int16]$bitmaps.Count)  # Number of images

# Calculate data offsets
$dataOffset = 6 + (16 * $bitmaps.Count)

# Collect image data
$imageData = @()
foreach ($bitmap in $bitmaps) {
    $imgMs = New-Object System.IO.MemoryStream
    $bitmap.Save($imgMs, [System.Drawing.Imaging.ImageFormat]::Png)
    $imageData += ,$imgMs.ToArray()
    $imgMs.Dispose()
}

# Write image directory entries
for ($i = 0; $i -lt $bitmaps.Count; $i++) {
    $size = $sizes[$i]
    $data = $imageData[$i]
    
    $writer.Write([byte]$(if ($size -ge 256) { 0 } else { $size }))  # Width (0 = 256)
    $writer.Write([byte]$(if ($size -ge 256) { 0 } else { $size }))  # Height (0 = 256)
    $writer.Write([byte]0)     # Color palette (0 = no palette)
    $writer.Write([byte]0)     # Reserved
    $writer.Write([int16]1)    # Color planes
    $writer.Write([int16]32)   # Bits per pixel
    $writer.Write([int32]$data.Length)  # Image data size
    $writer.Write([int32]$dataOffset)   # Offset to image data
    
    $dataOffset += $data.Length
}

# Write image data
foreach ($data in $imageData) {
    $writer.Write($data)
}

# Save ICO file
[System.IO.File]::WriteAllBytes($OutputPath, $ms.ToArray())

$writer.Dispose()
$ms.Dispose()

# Cleanup bitmaps
foreach ($bitmap in $bitmaps) {
    $bitmap.Dispose()
}

Write-Host "Saved ICO: $OutputPath" -ForegroundColor Green
Write-Host ""
Write-Host "To use in Visual Studio project:" -ForegroundColor Yellow
Write-Host "  1. Copy $OutputPath to your project's resources folder" -ForegroundColor Gray
Write-Host "  2. Update resource.rc to reference the new icon" -ForegroundColor Gray
Write-Host "  3. Rebuild the project" -ForegroundColor Gray
