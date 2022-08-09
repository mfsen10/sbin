function Test-Bitlocker ($BitlockerDrive) {
    try {
        Get-BitLockerVolume -MountPoint $BitlockerDrive -ErrorAction Stop
    } catch {
        Write-Output "Bitlocker was not found protecting the $BitlockerDrive drive. Terminating script!"
        exit 0
    }
}
function Get-KeyProtectorId ($BitlockerDrive) {
    $BitLockerVolume = Get-BitLockerVolume -MountPoint $BitlockerDrive
    $KeyProtector = $BitLockerVolume.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }
    while ($Keyprotector.keyprotectorid -lt 1)
    {
        Add-BitLockerKeyProtector -MountPoint $BitlockerDrive -RecoveryPasswordProtector
        $KeyProtector = $BitLockerVolume.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } 
    }
    return $KeyProtector.KeyProtectorId
}
function Invoke-BitlockerEscrow ($BitlockerDrive,$BitlockerKey) {
        BackupToAAD-BitLockerKeyProtector -MountPoint $BitlockerDrive -KeyProtectorId $BitlockerKey
        #Backup-BitLockerKeyProtector -MountPoint $BitlockerDrive -KeyProtectorId $BitlockerKey
        Write-Output "Attempted to escrow key in Azure AD" 
        exit 0;
}
$DriveLetter = $env:SystemDrive
Test-Bitlocker -BitlockerDrive $DriveLetter
$KeyProtectorId = Get-KeyProtectorId -BitlockerDrive $DriveLetter
Invoke-BitlockerEscrow -BitlockerDrive $DriveLetter -BitlockerKey $KeyProtectorId
