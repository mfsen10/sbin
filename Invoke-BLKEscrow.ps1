Function Set-SenseEnabled
    {
        Set-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender" "DisableAntiSpyware" 0 -ErrorAction SilentlyContinue
        Set-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender" "DisableRoutinelyTakingAction" 0 -ErrorAction SilentlyContinue
        Set-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableRealtimeMonitoring" 0 -ErrorAction SilentlyContinue
        Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" "DisableAntiSpyware" 0 -ErrorAction SilentlyContinue
        Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" "DisableRoutinelyTakingAction" 0 -ErrorAction SilentlyContinue
        Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableRealtimeMonitoring" 0 -ErrorAction SilentlyContinue
        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Sense" "Start" 2 -ErrorAction SilentlyContinue
        start-service sense -ErrorAction SilentlyContinue
        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" "Start" 2 -ErrorAction SilentlyContinue
        start-service windefend -ErrorAction SilentlyContinue
        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WdNisSvc" "Start" 3 -ErrorAction SilentlyContinue
        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\SecurityHealthService" "Start" 3 -ErrorAction SilentlyContinue
        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" "AutorunsDisabled" 0 -ErrorAction SilentlyContinue
        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WdNisSvc" "AutorunsDisabled" 0 -ErrorAction SilentlyContinue
        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Sense" "AutorunsDisabled" 0 -ErrorAction SilentlyContinue
        
        $mdePlatVer = (get-mpcomputerstatus).AMProductVersion
        if ($mdePlatVer -ne "4.18.2211.5")
        {
            set-location "C:\sophRM"
            write-warning "AV Platform Version not current 4.18.2211.5 (is $mdePlatVer)"
            invoke-webrequest "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/updt/2020/02/updateplatform_0456e6719c3ee098af03b785230ac020643fa1ac.exe" -outfile "C:\sophRm\AMD64_2001.10-updateplatform_0456e6719c3ee098af03b785230ac020643fa1ac.exe"
            start-process .\AMD64_2001.10-updateplatform_0456e6719c3ee098af03b785230ac020643fa1ac.exe
            Invoke-WebRequest "https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/defu/2022/11/updateplatform_b5a2679b058450feb68b78736e525f8f5ac657fb.exe" -outfile "C:\sophRm\AMD64_2211.5-updateplatform_b5a2679b058450feb68b78736e525f8f5ac657fb.exe"
            start-process .\AMD64_2211.5-updateplatform_b5a2679b058450feb68b78736e525f8f5ac657fb.exe
        }else{
            Write-Output "MDE AV Platform Version current as of 2023\01\24 ($mdePlatVer)"
        }

    }

Function Invoke-BitlockerEscrow ($BitlockerDrive,$BitlockerKey) 
    {
        #Escrow the key into Azure AD
        #TODO: add proxy avoidance method
        try {
            BackupToAAD-BitLockerKeyProtector -MountPoint $BitlockerDrive -KeyProtectorId $BitlockerKey 
            #BackupToAAD-BitLockerKeyProtector -mountpoint $Env:systemdrive -KeyProtectorID $((((Get-BitLockerVolume -mountpoint $Env:systemdrive).KeyProtector)|Where-Object {$_.KeyProtectortype -eq 'RecoveryPassword'}).keyProtectorID)
            Backup-BitLockerKeyProtector -MountPoint $BitlockerDrive -KeyProtectorId $BitlockerKey -ErrorAction SilentlyContinue
            Write-Output "`nAttempted to escrow key in Azure AD AND on-prem AD - Please verify manually!`n"
        } catch {
            Write-Error "Azure escrow failed, exiting!"
            Stop-Transcript
            exit 2
        }
    }

    Function Remove-SuperfluousRecoPasswds
    {
        $recoverykeysWithPasswds=(((Get-BitLockerVolume -mountpoint $Env:systemdrive).KeyProtector)|Where-Object {$_.KeyProtectortype -eq 'RecoveryPassword'}).keyProtectorID
        $countKeys=$recoverykeysWithPasswds.count
        Write-Output "Found $countkeys KeyProtectorID's with an associated RecoveryPassword, attempting to trim to one."
        foreach ($keyprotectorid in $recoverykeysWithPasswds)
            {
                while ($countKeys -gt 1)
                    {
                        Remove-BitLockerKeyProtector -mountpoint $env:systemdrive -KeyProtectorId $keyprotectorid
                        $recoverykeysWithPasswds=(((Get-BitLockerVolume -mountpoint $Env:systemdrive).KeyProtector)|Where-Object {$_.KeyProtectortype -eq 'RecoveryPassword'}).keyProtectorID
                        $countKeys=$recoverykeysWithPasswds.count
                        Write-Output "$countkeys KeyProtectorID's with an associated RecoveryPassword remain."
                    }
            }
        #BackupToAAD-BitLockerKeyProtector -mountpoint $Env:systemdrive -KeyProtectorID $((((Get-BitLockerVolume -mountpoint $Env:systemdrive).KeyProtector)|Where-Object {$_.KeyProtectortype -eq 'RecoveryPassword'}).keyProtectorID)
    }


Function Remove-UnencryptedRecoPasswds
    {
        $recoverykeysWithPasswds=(((Get-BitLockerVolume -mountpoint $Env:systemdrive).KeyProtector)|Where-Object {$_.KeyProtectortype -eq 'RecoveryPassword'}).keyProtectorID
        $countKeys=$recoverykeysWithPasswds.count
        Write-Output "Found $countkeys KeyProtectorID's with an associated RecoveryPassword, attempting to remove."
        $encryptstatus = (get-bitlockervolume -MountPoint $env:systemdrive).EncryptionPercentage
        $blstatus = (get-bitlockervolume -MountPoint $env:systemdrive).VolumeStatus
        foreach ($keyprotectorid in $recoverykeysWithPasswds)
            {
                if ($countKeys -eq 1 -and $encryptstatus -eq 0 -and $blstatus -eq "FullyDecrypted")
                    {
                        Remove-BitLockerKeyProtector -mountpoint $env:systemdrive -KeyProtectorId $keyprotectorid
                        $recoverykeysWithPasswds=(((Get-BitLockerVolume -mountpoint $Env:systemdrive).KeyProtector)|Where-Object {$_.KeyProtectortype -eq 'RecoveryPassword'}).keyProtectorID
                        $countKeys=$recoverykeysWithPasswds.count
                        Write-Output "$countkeys KeyProtectorID's with an associated RecoveryPassword remain."
                        # Stop-Transcript
                        # exit 0;
                    }
            }
        #BackupToAAD-BitLockerKeyProtector -mountpoint $Env:systemdrive -KeyProtectorID $((((Get-BitLockerVolume -mountpoint $Env:systemdrive).KeyProtector)|Where-Object {$_.KeyProtectortype -eq 'RecoveryPassword'}).keyProtectorID)
    }

Function Set-SingleRecoPasswd ($BitlockerDrive) 
    {
        $BitLockerVolume = Get-BitLockerVolume -MountPoint $BitlockerDrive
        $KeyProtector = $BitLockerVolume.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } 
        $KeyProtectorCount = $Keyprotector.count
        #$BLStatus = (get-bitlockervolume -MountPoint $env:systemdrive).VolumeStatus
        if ($KeyProtectorCount -gt 1)
            {
                Write-Warning "Too many keyprotector recovery passwords on system drive ($KeyprotectorCount total)"
                Remove-SuperfluousRecoPasswds
        }
        
        $encryptstatus = (get-bitlockervolume -MountPoint $env:systemdrive).EncryptionPercentage
        $blstatus = (get-bitlockervolume -MountPoint $env:systemdrive).VolumeStatus
        if ($encryptstatus -eq 0 -and $blstatus -eq "FullyDecrypted")
            {
                Write-Output "Bitlocker is not enabled on system drive, removing recovery keys if existent"
                Remove-UnencryptedRecoPasswds
            }
        
        $BitLockerVolume = Get-BitLockerVolume -MountPoint $BitlockerDrive
        $KeyProtector = $BitLockerVolume.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } 
        $KeyProtectorCount = $Keyprotector.count
        $encryptstatus = (get-bitlockervolume -MountPoint $env:systemdrive).EncryptionPercentage
        $blstatus = (get-bitlockervolume -MountPoint $env:systemdrive).VolumeStatus
        if ($KeyProtectorCount -lt 1 -and $encryptstatus -ne 0 -and $blstatus -ne "FullyDecrypted")
            {
                Write-Warning "No KeyProtector found for systemdrive, and encryption is enabled! Creating Recovery Key and PW."
                Add-BitLockerKeyProtector -MountPoint $BitlockerDrive -RecoveryPasswordProtector
                $KeyProtector = $BitLockerVolume.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } 
            }
        
    }

Function Get-KeyProtectorId ($BitlockerDrive) 
    {
        $BitLockerVolume = Get-BitLockerVolume -MountPoint $BitlockerDrive
        $KeyProtector = $BitLockerVolume.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } 
        return $KeyProtector.KeyProtectorId
        #(((Get-BitLockerVolume -mountpoint $Env:systemdrive).KeyProtector)|Where-Object {$_.KeyProtectortype -eq 'RecoveryPassword'}).keyProtectorID
    }

Function Test-Bitlocker ($BitlockerDrive) 
    {
        #Tests the drive for existing Bitlocker keyprotectors
        try {
            Get-BitLockerVolume -MountPoint $BitlockerDrive -ErrorAction Stop 
        } catch {
            Write-Warning "Bitlocker was not found protecting the system drive '$BitlockerDrive'!"
        }
    }

Function Invoke-EscrowBitlockerToAAD
    {
        Test-Bitlocker -BitlockerDrive $DriveLetter Out-Null
        Set-SingleRecoPasswd ($DriveLetter)
        $KeyProtectorId = Get-KeyProtectorId -BitlockerDrive $DriveLetter
        Invoke-BitlockerEscrow -BitlockerDrive $DriveLetter -BitlockerKey $KeyProtectorId
    }

$DriveLetter = $env:SystemDrive
$tpmpresent = (Get-TPM).tpmpresent
if ($tpmpresent)
    {
        Invoke-EscrowBitlockerToAAD
    }
Set-SenseEnabled
