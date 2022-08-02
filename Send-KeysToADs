<#
.SYNOPSIS
    Escrow (Backup) the existing Bitlocker key protectors to Azure AD (Intune)
.DESCRIPTION
    This script will verify the presence of existing recovery keys and have them escrowed (backed up) to Azure AD
    Great for switching away from MBAM on-prem to using Intune and Azure AD for Bitlocker key management
.INPUTS
    None
.NOTES
    Version       : 1.0
    Author        : Michael Mardahl
    Blogging on   : www.msendpointmgr.com
    Creation Date : 11 January 2021
    Purpose/Change: Add local ADDS backup escrow and let it error out if there's a policy mismatch.
    Editor:       : MF@CFI~20220802
    License       : MIT (Leave author credits)
.EXAMPLE
    Execute script as system or administrator
    .\Invoke-EscrowBitlockerToAAD.ps1
.NOTES
    If there is a policy mismatch, then you might get errors from the built-in cmdlet BackupToAAD-BitLockerKeyProtector.

#>
#region declarations
$DriveLetter = $env:SystemDrive
#endregion declarations
#region functions
function Test-Bitlocker ($BitlockerDrive) {
    #Tests the drive for existing Bitlocker keyprotectors
    try {
        Get-BitLockerVolume -MountPoint $BitlockerDrive -ErrorAction Stop
    } catch {
        Write-Output "Bitlocker was not found protecting the $BitlockerDrive drive. Terminating script!"
        exit 0
    }
}
function Get-KeyProtectorId ($BitlockerDrive) {
    #fetches the key protector ID of the drive
    $BitLockerVolume = Get-BitLockerVolume -MountPoint $BitlockerDrive
    $KeyProtector = $BitLockerVolume.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }
    return $KeyProtector.KeyProtectorId
}
function Invoke-BitlockerEscrow ($BitlockerDrive,$BitlockerKey) {
    #Escrow the key to AAD and AD 
    # try {
        BackupToAAD-BitLockerKeyProtector -MountPoint $BitlockerDrive -KeyProtectorId $BitlockerKey
        Write-Output "Attempted to escrow key in Azure AD" 
        ## can't do this here yet because the local AD is not configured to accept them. 
        #Backup-BitLockerKeyProtector -MountPoint $BitlockerDrive -KeyProtectorId $BitlockerKey 
        #Write-Output "...and domain ADDS"
        exit 0;
    # } catch {
    #     Write-Error "This should never have happend? Debug me!"
    #     exit 1
    # }
}
#endregion functions
#region execute
Test-Bitlocker -BitlockerDrive $DriveLetter
$KeyProtectorId = Get-KeyProtectorId -BitlockerDrive $DriveLetter
Invoke-BitlockerEscrow -BitlockerDrive $DriveLetter -BitlockerKey $KeyProtectorId
#endregion execute
