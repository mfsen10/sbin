<#
Invoke-SophosRemoval.ps1
.SYNOPSIS
Stops Sophos AutoUpdate services, sets bitlocker disable counter, collects installed Sophos modules, then runs through an ordered list to make 3x attempts of removal for the MSI-based packages, and closes out with
the removal of Endpoint Defense EXE-based package. I'd be happy to Install-Module PackageManagement but it's non-native depedency, so roll my own. 
*~~. Gr33tz to JC@CFI, Sup3rLativ3@GitHub, mardhal@msendpointmgr .~~*
.DESCRIPTION
@author: MF@CFI~20220719-29
.LINK
 https://support.sophos.com/support/s/article/KB-000033686?language=en_US
.LINK
https://github.com/Sup3rLativ3/Remove-Sophos/blob/master/Remove-Sophos.ps1
.LINK
https://github.com/mardahl/PSBucket/blob/master/Invoke-EscrowBitlockerToAAD.ps1
#>
#requires -runasadministrator

#### fn declarations
Function Test-Eicar
    {
        Write-Output "Attempting EICAR execution for AV validation"
        invoke-webrequest "https://secure.eicar.org/eicar.com" -outfile "$env:windir\temp\eicar.com" -ErrorAction SilentlyContinue
        Start-process "$env:windir\temp\eicar.com" -ErrorAction SilentlyContinue
    }

Function Confirm-Program_Installed( $programName ) 
    {
        $wmi_check = (Get-CimInstance -Property "Name" -Class "Win32_Product" -Filter "Name LIKE '$programName%'").name.length -gt 0
        return $wmi_check;
    }

Function Remove-MSIPkg 
    {
        Param ($MarkedAppGUID)
        $ChamberFiredTstamp = "$(get-date -format 'yyyyMMdd-HHMMss')"
        #Write-Output "    DEBUG: MSIexec nixing $markedappguid at $ChamberFiredTstamp "
        #TODO: execute uninstall
        $MSIexec = "$Env:windir\system32\msiexec.exe"
        #Set-Location -Path $Kitchen
        $NamedLogfile = "UninstLog-$MarkedAppGUID-$ChamberFiredTstamp.txt"
        $arglist = "/X $MarkedAppGUID /qn /norestart /L*v $NamedLogfile"
        Write-Output "`n    Removing via $MSIexec $arglist"
        
        $doRemove = Start-Process -FilePath $MSIexec -ArgumentList $arglist -Wait -PassThru

        while ($doRemove.HasExited -eq $false )
            {
                Write-Host "Waiting for $process..."
                Start-Sleep -s 1
            }
        $exitCode = $doRemove.ExitCode
        if ($exitCode -ne 0 -and $exitcode -ne 3010)
            {
                Write-Host "    MSI exit code $exitCode" -ForegroundColor red
                Write-Output "    Get MSIexec Log Here:    $Kitchen\$NamedlogFile"
                $failSrc = Get-Content -Path $Kitchen\$NamedlogFile |select-string "error"
                Write-Error "Error Log Dump:`n$failSrc"
                Stop-Transcript
                $MillerTime = 9990000+$exitCode
                exit $MillerTime; 
            }else{
                Write-Output "    REMOVED MSI $MarkedAppGUID!"
                if ($exitCode -eq 3010)
                    {
                        Write-Output "Last App reported Reboot Required, throwing userland GUID reboot request"
                        #todo: figure out a method of sleeping on msg prompt so SED removal can complete before user bails the machine out of it.  this sleep works but might open a cmd window for timeout phase and the escaped linebreaks don't work.
                        #Start-Process -FilePath "$env:windir\system32\cmd.exe" -Args "/C timeout 60 && msg.exe * Sophos removal has completed and requires a reboot - Please reboot this machine as soon as possible to avoid performance issues\`n\`nThank you - Microsoft Defender Deployment Administrator"
                        Start-Process -FilePath "$env:windir\system32\MSG.exe" -Args "* Sophos removal has completed and requires a reboot - Please reboot this machine as soon as possible to avoid performance issues`n`nThank you - Microsoft Defender Deployment Administrator"
                    }

            }
    }

Function Invoke-MSIrmEngine
    {
        Param ($Application)
        Write-Output "    Attempting to uninstall $($Application.Name)"
        try
            {
                $InChamberAppGUID = $Application.IdentifyingNumber
                $InChamberAppName = $Application.Name
                Remove-MSIPkg $InChamberAppGUID
                $RmAttemptCounter = 1
                $StillInstalled = $TRUE
                Write-Output "    Confirming that $InChamberAppName ($inchamberappguid) is uninstalled"
                $StillInstalled = Confirm-Program_Installed $InChamberAppName
                While ($StillInstalled -and $RmAttemptCounter -lt 4)
                    {
                        Write-Output "    $InChamberAppName was not uninstalled, trying again... ($RmAttemptCounter)" 

                        Remove-MSIPkg $InChamberAppGUID

                        $RmAttemptCounter++
                    }
                If ($StillInstalled)
                    {
                        Write-Error "`n`nERROR: Unable to uninstall $InChamberAppName after $RmAttemptCounter times"
                        Stop-Transcript
                        exit 15;
                    }Else{
                        Write-Output "Successfully removed $InChamberAppName"
                        $RmAttemptCounter = 0
                        Test-Eicar
                    }
            }catch{
                Write-Error "Error: Failed to remove $InChamberAppName"
            }
    } 

Function Remove-SED 
    { 
        Write-Output "`nChecking if the final Endpoint Defense module is installed..."
        $SEDAppName = "Sophos Endpoint Defense"
        $SEDinstalled = Test-Path "$Env:ProgramFiles\Sophos\Endpoint Defense\SEDService.exe"
        if ($SEDinstalled)
            {
                try 
                    {
                        $seduninstexe = "$Env:ProgramFiles\Sophos\Endpoint Defense\SEDuninstall.exe"
                        Write-Output "    Attempting to uninstall $SedAppName"
                        start-process $sedUninstexe -arg "/silent" -Wait
                        $SEDrmCtr = 1
                        $SEDZombie = $TRUE
                        Write-Output "    Confirming that $SEDAppName is uninstalled"
                        #$SEDZombie = Confirm-Program_Installed $SEDAppName
                        $SEDZombie = Test-Path "$Env:ProgramFiles\Sophos\Endpoint Defense\SEDService.exe"
                        While ($SEDZombie -and $SEDrmCtr -lt 4)
                            {
                                Write-Output "    $SEDAppName was not uninstalled, trying again... ($sedrmctr)" 
                                start-process $sedUninstexe -arg "/silent" -Wait
                                $SEDrmCtr++
                            }
                        If ($StillInstalled)
                            {
                                Write-Error "`n`nERROR: Unable to uninstall $SEDAppName after $sedrmctr times"
                            }
                        Else
                            {
                                Write-Output "Successfully removed $SedAppName"
                                $SEDrmCtr = 0
                            }
                        Write-Output "Successfully removed $SedAppName"
                        Test-Eicar
                    }catch{
                        Write-Error "Error: Failed to remove $SedAppName"
                        Test-Eicar
                    }
            }else{
                Write-Output "    $SedAppName not found."
                Write-Output "`nNo further Sophos AV modules found as of $(Get-Date)"
            }
    }

Function Invoke-SophosZap
    {
        Write-Output "`n`nAttempting Sophos Zap!!!!"
        #TODO: reduce hold timer
        Write-Warning -Message "Holding here for 30 seconds to cover latency. If you want to Ctrl-C bailout..."
        $ZapPath = "$Kitchen\SophosZap.exe"
        $PrevZap = Test-Path $ZapPath
        if (!$PrevZap)
            {
                Invoke-WebRequest -Uri "https://github.com/mfsen10/bin/raw/main/SophosZap-v1-4-146-20220728.exe" -outfile "$Kitchen\SophosZap.exe" 
                start-sleep 30
            }
        $ZapLogPath = "$env:temp\SophosZap log.txt"
        $PrevZapLog = Test-Path $ZapLogPath
        if ($PrevZapLog)
            {
                Remove-Item -path $ZapLogPath
            }
        start-process "$Kitchen\SophosZap.exe" -arg "--confirm" -Wait
        $failSauce = Get-Content 'C:\Users\MFINNE~1\AppData\Local\Temp\SophosZap log.txt' |select-string "ERROR"
        $ZapFailed = ($null -ne $failSauce.length)
        if ($ZapFailed) 
            {
                Write-Error "Zapping Failed; Reporting errors::`n$failSauce"
            }
    }

Function Get-InstalledSophosMSI
    {
        Write-Output "Searching for installed Sophos Apps..."
        $instSophApps = Get-CimInstance -property Name,IdentifyingNumber -Class "win32_product" -Filter "Name LIKE 'Sophos%' AND NOT Name='Sophos Endpoint Defense' AND NOT Name Like '%SafeGuard Management%'  AND NOT Name Like '%Sophos Management%'"
        #$instSophApps = Get-CimInstance -property Name,IdentifyingNumber -Class "win32_product" -Filter "Name LIKE 'Sophos%' AND NOT Name='Sophos Endpoint Defense' AND NOT Name LIKE '%safeguard%'"
        $AppCount = $instSophApps.Name.count
        if ($appcount -gt 0)
            {
                Write-Warning "    Found $AppCount Sophos MSI modules installed, beginning removals"
            }
        return $instSophApps
    }

Function Initialize-OrderedSophosMSIsForUninstall
    {
        Param ($installedophosAppArr)
        if($installedophosAppArr.name.count -gt 0)
            {
                $removalctr = 0;
                Write-Output "    Sophos apps remain installed."
                #Suspend-BitlockerEncx $DriveLetter
                # guardrails removed, too much end user fuss.
                Stop-SophosServices
                foreach ($NamedSophappToRm in $NamedSophAppRmOrder)
                    {
                        Write-output "`nStep $removalctr. $NamedSophappToRm to be removed"
                        $rmStepping = 0;
                        foreach($FoundSophAppBlob in $installedophosAppArr)
                            {
                                $NamedInstApp = $FoundSophAppBlob.name
                                if ($NamedInstApp -like "$NamedSophAppToRm*")
                                    {
                                        $removalappGuid=$FoundSophAppBlob.IdentifyingNumber
                                        Write-Output "    $NamedInstApp is installed, matches current place in ordered removal. Removing $removalappGuid"
                                        Write-Debug "($removalctr found in $rmStepping.)" 
                                        Invoke-MSIrmEngine $FoundSophAppBlob
                                    }else{
                                        Write-Debug "    $NamedSophappToRm not in slot, skipping."
                                    }
                                $rmStepping++;
                            }
                        $removalctr++;
                    }
            }else{
                Write-Output "No Further Sophos MSI's found"
            }
    }

Function Suspend-BitlockerEncx ($Driveletter)
    {
        $SysDrvEncrpted = Test-Bitlocker -BitlockerDrive $DriveLetter
        
        ##Suspend Bitlocker to prevent lock - we're modifying kernel modules with the AV stuff which probably will trip recovery. 
        Write-Output "`nSuspending bitlocker on $DriveLetter for two reboots. ProtectionStatus should report Off:"
        if ($SysDrvEncrpted)
            {
                try{
                    #TODO: Execute
                    $SuspensionStatus = (Suspend-BitLocker -MountPoint $DriveLetter -RebootCount 2).ProtectionStatus
                    Write-Output "    Protection Status: $SuspensionStatus"
                }
                catch
                {
                    Write-Error "Unable to suspend Bitlocker, halting"
                    Stop-Transcript
                    exit 3;
                }
            }else{
                Write-Output "    Skipping BL suspension"
            }
    }
    
Function Stop-SophosServices
    {
        Write-Output "`nAttempting to halt Sophos AutoUpdate Service."
        if ((get-service -name "Sophos AutoUpdate Service" -ErrorAction SilentlyContinue).Name.Length -gt 0)
        {
            try
                {
                    Write-Debug "DEBUG: would be stopping $((Get-Service -Name "Sophos AutoUpdate Service").Displayname)"
                    #TODO: Execute
                    Stop-Service -Name "Sophos AutoUpdate Service" -PassThru
                }
            catch
                {
                    Write-Error "Unable to stop the AutoUpdate Service"
                }
        }else{
            Write-Output "    No Sophos AutoUpdate Service, skipping disablement."
        }
    }


Function Invoke-BitlockerEscrow ($BitlockerDrive,$BitlockerKey) 
    {
        #Escrow the key into Azure AD
        #TODO: add proxy avoidance method
        try {
            BackupToAAD-BitLockerKeyProtector -MountPoint $BitlockerDrive -KeyProtectorId $BitlockerKey -ErrorAction SilentlyContinue
            #BackupToAAD-BitLockerKeyProtector -mountpoint $Env:systemdrive -KeyProtectorID $((((Get-BitLockerVolume -mountpoint $Env:systemdrive).KeyProtector)|Where-Object {$_.KeyProtectortype -eq 'RecoveryPassword'}).keyProtectorID)
            Backup-BitLockerKeyProtector -MountPoint $BitlockerDrive -KeyProtectorId $BitlockerKey -ErrorAction SilentlyContinue
            Write-Output "`nAttempted to escrow key in Azure AD AND on-prem AD - Please verify manually!`n"
        } catch {
            Write-Error "Azure escrow failed!"
            #Stop-Transcript
            #exit 2
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

Function Invoke-WriteLog ([string]$LogString) 
    {
        $Logfile = ".\SophRM_$env:computername.log"
        $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
        $LogMessage = "$Stamp $LogString"
        Add-content $LogFile -value $LogMessage
        Start-Transcript -Append $Logfile
    }

Function Build-Kitchen 
    {
        $NamedKitchen = "SophRm"
        $KitchenPath = "$Env:SystemDrive\$NamedKitchen"
        #$logpathexists=(Get-Item $KitchenPath).name -gt 0;
        if (!(Test-Path $KitchenPath))
        {
            Write-Output "Kitchen not found, building $KitchenPath"
            New-Item -Path "$KitchenPath" -ItemType Directory 
        }
        Set-Location -Path $KitchenPath
        return $KitchenPath;
    }

Function Get-SenseStatus
    {
        Write-Output "Checking Sense (Defender) service status"
        $senseis = (get-service sense).status
        Write-Output "Defender Service is $senseis"
        $sensestatus = $senseis -ne "running"
        $sensectr = 1
        while ($sensestatus -and $sensectr -lt 4)
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
                    Invoke-WebRequest "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/updt/2020/02/updateplatform_0456e6719c3ee098af03b785230ac020643fa1ac.exe" -outfile "C:\sophRm\AMD64_2001.10-updateplatform_0456e6719c3ee098af03b785230ac020643fa1ac.exe"
                    start-process .\AMD64_2001.10-updateplatform_0456e6719c3ee098af03b785230ac020643fa1ac.exe
                    Invoke-WebRequest "https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/defu/2022/11/updateplatform_b5a2679b058450feb68b78736e525f8f5ac657fb.exe" -outfile "C:\sophRm\AMD64_2211.5-updateplatform_b5a2679b058450feb68b78736e525f8f5ac657fb.exe"
                    start-process .\AMD64_2211.5-updateplatform_b5a2679b058450feb68b78736e525f8f5ac657fb.exe
                }else{
                    Write-Output "MDE AV Platform Version current as of 2023\01\24 ($mdePlatVer)"
                }
                $sensectr++
            }
        if ($sensestatus)
            {
                Write-Output "Defender is not running, bailing out of Sophos Removal"
                Stop-Transcript
                exit 10
            }
    }
Function Get-AMrunningStatus 
    {
        try 
            {
            Get-MpComputerStatus
            }
        catch 
            {
            {1:Write-Error "Defender/Sense services are not in a servicable state, cannot continue with Sophos removal"; Stop-Transcript; exit 49;}
         }

        $AMrunningstat=(Get-MpComputerStatus).AMrunningMode
        if ($AMrunningstat -eq "Not Running")
            {
                Write-Error "Sense svc enabled but Defender is not currently running at all, exiting"
                Stop-Transcript
                exit 50;
            }
        if ($AMrunningstat -ne "Normal" -and $AMrunningstat -ne "EDR Block Mode")
            {
                Write-Error "Defender reports an unverified running status - cannot safely remove Sophos AV, exiting"
                Stop-Transcript
                exit 50;
            }
        Write-Host "Defender status detection gauntlet passed with: $AMrunningstat - beginning sophos removal procedure.`n"
    }
#endregion functions

#region declarations
$NamedSophAppRmOrder = "Sophos Remote Management System",
"Sophos Network Threat Protection",
"Sophos Client Firewall",
"Sophos Anti-Virus",
"Sophos AutoUpdate",
"Sophos Diagnostic Utility",
"Sophos Exploit Prevention",
"Sophos CryptoGuard",
"Sophos Clean",
"Sophos Patch Agent",
"Sophos System Protection"

$RmAttemptCounter = 0
$removalctr = 0
$rmStepping = 0
$DriveLetter = $env:SystemDrive
Clear-Host
Write-Host "******************************" -ForegroundColor Magenta
Write-Host "** Sophos uninstall script. **" -ForegroundColor Magenta
Write-Host "******************************`n`n`n" -ForegroundColor Magenta
#endregion declarations


#region execute
$Kitchen=Build-Kitchen
Write-Output "Working from $Kitchen"
Invoke-WriteLog ("`n`nBeginning Sophos Removal Process")
Get-SenseStatus
Get-AMrunningStatus

$tpmpresent = (Get-TPM).tpmpresent
if ($tpmpresent)
    {
        Invoke-EscrowBitlockerToAAD
    }

Write-Output "`nSearching for installed Sophos Apps..."
Initialize-OrderedSophosMSIsForUninstall $(Get-InstalledSophosMSI)
Remove-SED
    #region safeguard
    $NamedSafeGuardAppRmOrder = "Sophos SafeGuard Client Configuration",
    "Sophos SafeGuard Client",
    "Sophos SafeGuard Preinstall"
    $NamedSophAppRmOrder = $NamedSafeGuardAppRmOrder
    Write-Output "`nSearching for installed SafeGuard Apps..."
    Initialize-OrderedSophosMSIsForUninstall $(Get-InstalledSophosMSI)
    #Invoke-SophosZap
    #can't zap even with safeguard removed, leaving presumably functional code escaped for posterity.
    # endregion SafeGuard
Stop-Transcript
exit 0;
#endregion execute
