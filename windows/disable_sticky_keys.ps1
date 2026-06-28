try {
    # disable for current user
    Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Value "506"

    # disable system-wide
    Set-ItemProperty -Path "HKU\.DEFAULT\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Value "506"

    Write-Host "[SUCCESS] Sticky Keys has been disabled system-wide."

} catch {
    Write-Host "[ERROR] $($_.Exception.Message)"
}
