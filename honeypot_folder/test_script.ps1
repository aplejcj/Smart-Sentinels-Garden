# --- ฟังก์ชันสำหรับล้างไฟล์ชั่วคราว ---
function Clear-TemporaryFiles {
    $tempPath = $env:TEMP
    Write-Host "Locating temporary files in: $tempPath"
    
    $items = Get-ChildItem -Path $tempPath -Recurse -Force -ErrorAction SilentlyContinue
    if ($items) {
        $totalSize = ($items | Measure-Object -Property Length -Sum).Sum / 1MB
        Write-Host "Found $($items.Count) temporary items. Total size: $($totalSize.ToString('F2')) MB."
        
        
        Write-Host "Simulation complete. Files were not actually deleted."
    } else {
        Write-Host "No temporary files found to clear."
    }
}

Write-Host "[BENIGN UTILITY] Running system cleanup simulation..."
Clear-TemporaryFiles
Write-Host "[BENIGN UTILITY] Task finished successfully."
Start-Sleep -Seconds 3