<#
rmSophos.ps1
.Synopsis
Stops Sophos AutoUpdate services, sets bitlocker disable counter, collects installed Sophos modules, then runs through an ordered list to make 3x attempts of removal for the MSI-based packages, and closes out with
the removal of Endpoint Defense EXE-based package.   
*~~ Gr33tz to JC@CFI, Sup3rLativ3@GitHub ~~*
.Description
@author: MF@CFI~20220719
.Link
 https://support.sophos.com/support/s/article/KB-000033686?language=en_US
.Link
https://github.com/Sup3rLativ3/Remove-Sophos/blob/master/Remove-Sophos.ps1
#>
#requires -runasadministrator

### Housekeeping
Clear-Host
$RmAttemptCounter = 0
$removalctr = 0
$rmStepping = 0

#### Welcome banner
Write-Host "******************************" -ForegroundColor Magenta
Write-Host "** Sophos uninstall script. **" -ForegroundColor Magenta
Write-Host "******************************`n`n`n" -ForegroundColor Magenta

#### fn declarations
Function Confirm-Program_Installed( $programName ) 
    {
        $wmi_check = (Get-WMIObject -Property "Name" -Class "Win32_Product" -Filter "Name LIKE '$programName%'").name.length -gt 0
        return $wmi_check;
    }

Function Remove-MSIPkg 
    {
        Param ($MarkedAppGUID)
        $ChamberFiredTstamp = "$(get-date -format 'yyyyMMdd-HHMMss')"
        #Write-Output "    DEBUG: MSIexec nixing $markedappguid at $ChamberFiredTstamp "
        #TODO: execute uninstall
        $MSIexec = "$Env:windir\system32\msiexec.exe"
        Set-Location -Path $Kitchen
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
        if ($exitCode -ne 0)
            {
                Write-Host "    MSI exit code $exitCode" -ForegroundColor red
                Write-Output "    Get MSIexec Log Here:    $Kitchen\$NamedlogFile"
                $failSrc = Get-Content -Path $Kitchen\$NamedlogFile |select-string "error"
                Write-Error "Error Log Dump:`n$failSrc"
                exit $exitCode;
            }else{
                Write-Output "    REMOVED MSI $MarkedAppGUID!"
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
                        exit 1;
                    }Else{
                        Write-Output "Successfully removed $InChamberAppName"
                        $RmAttemptCounter = 0
                    }
            }catch{
                Write-Error "Error: Failed to remove $InChamberAppName"
            }
    } 

Function Remove-SED 
    { 
        Write-Output "`nChecking if the final Endpoint Defense module is installed..."
        $SEDAppName = "Sophos Endpoint Defense"
        $SEDinstalled = Confirm-Program_Installed $SEDAppName
        if ($SEDinstalled)
            {
                try 
                    {
                        $seduninstexe = "C:\Program Files\Sophos\Endpoint Defense\SEDuninstall.exe"
                        Write-Output "    Attempting to uninstall Sophos Endpoint Defense"
                        start-process $sedUninstexe -arg "/silent" -Wait
                        $SEDrmCtr = 1
                        $SEDZombie = $TRUE
                        Write-Output "    Confirming that $InChamberAppName ($inchamberappguid) is uninstalled"
                        $SEDZombie = Confirm-Program_Installed $SEDAppName
                        While ($SEDZombie -and $SEDrmCtr -lt 4)
                            {
                                Write-Output "    $SEDAppName was not uninstalled, trying again... ($sedrmctr)" 
                                start-process $sedUninstexe -arg "/silent" -Wait
                                $SEDrmCtr++
                            }
                        If ($StillInstalled)
                            {
                                Write-Error "`n`nERROR: Unable to uninstall $SEDAppName after $sedrmctr times"
                                Invoke-SophosZap
                            }
                        Else
                            {
                                Write-Output "Successfully removed $SedAppName"
                                $SEDrmCtr = 0
                            }
                        Write-Output "Successfully removed Sophos Endpoint Defense"
                    }catch{
                        Write-Error "Error: Failed to remove Sophos Endpoint Defense"
                        Invoke-SophosZap
                    }
            }else{
                Write-Output "`nNo further Sophos apps are installed as of $(Get-Date)" -ForegroundColor Green
                exit 0;
            }
    }

Function Invoke-SophosZap
    {
        Write-Output "`n`nAttempting Sophos Zap!!!!"
        #TODO: Execute Sophos Zap burn-down
        Write-Warning -Message "Holding up for 30 seconds for latency. If you want to Ctrl-C bailout..."
        invoke-webrequest https://github.com/mfsen10/bin/raw/main/SophosZap-v1-4-146-20220728.exe -outfile "$Kitchen\SophosZap.exe" 
        start-sleep 30
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
                exit 3;
            }
    }

Function Get-InstalledSophosMSI
    {
        Write-Output "Searching for installed Sophos Apps..."
        # note we'll be removing the exe-based installer after all this MSI package removal.
        $instSophApps = Get-WmiObject -property "Name,IdentifyingNumber" -Class "win32_product" -Filter "Name LIKE 'Sophos%' AND NOT Name='Sophos Endpoint Defense'"
        #Get-WMIObject -Query "SELECT Name,IdentifyingNumber FROM Win32_Product Where Name Like 'Sophos%' and not name='Sophos Endpoint Defense'"
        return $instSophApps
    }

Function Initialize-OrderedSophosMSIsForUninstall
    {
        Param ($installedophosAppArr)
        if(!$null -eq $installedophosAppArr)  
            {
                $removalctr = 0;
                foreach ($NamedSophappToRm in $NamedSophAppRmOrder)
                    {
                        Write-output "`nStep $removalctr. $NamedSophappToRm to be removed"
                        $rmStepping = 0;
                        foreach($FoundSophAppBlob in $installedophosAppArr)
                            {
                                $NamedInstApp = $FoundSophAppBlob.name
                                #write-output "      Matches $NamedInstApp ?"
                                if ($NamedInstApp -like "$NamedSophAppToRm*")
                                    {
                                        $removalappGuid=$FoundSophAppBlob.IdentifyingNumber
                                        Write-Output "    $NamedInstApp is installed, matches current place in ordered removal. Removing $removalappGuid"
                                        #Write-Output $FoundSophAppBlob
                                        Write-Debug "($removalctr found in $rmStepping.)" 
                                        #Write-Output "`n`n`n`n`n$FoundSophAppBlob`n`n`n`n"
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

function Test-Bitlocker ($BitlockerDrive) 
    {
        #Tests the drive for existing Bitlocker keyprotectors
        try {
            Write-Output "    Checking System Drive Encryption Status"
            Get-BitLockerVolume -MountPoint $BitlockerDrive -ErrorAction SilentlyContinue
        } catch {
            Write-Output "    Bitlocker was not found protecting the $BitlockerDrive system drive."
        }
    }
        
Function Suspend-BitlockerEncx
    {
        $DriveLetter = $env:SystemDrive

        $SysDrvEncrpted = Test-Bitlocker -BitlockerDrive $DriveLetter
        
        ##Suspend Bitlocker to prevent lock - we're modifying kernel modules with the AV stuff which probably will trip recovery. 
        Write-Output "`nSetting bitlocker suspension for two reboots. ProtectionStatus should report Off:"
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
                    exit 1;
                }
            }else{
                Write-Output "    Skipping BL suspension"
            }
    }
    
Function Stop-SophosServices
    {
        Write-Output "Attempting to halt Sophos AutoUpdate Service."
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

Function Build-Kitchen 
    {
        $NamedKitchen = "SophRm"
        $KitchenPath = "$Env:SystemDrive\$NamedKitchen"
        #$logpathexists=(Get-Item $KitchenPath).name -gt 0;
        if (!(Test-Path $kitchenPath))
        {
            Write-Output "Kitchen not found, building $KitchenPath"
            New-Item -Path "$KitchenPath" -ItemType Directory 
        }
        Set-Location -Path $KitchenPath
        return $KitchenPath;
    } 

########################################################################################################
#### var defs
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
"Sophos SafeGuard Client Configuration",
"Sophos SafeGuard Client",
"Sophos SafeGuard Preinstall"


#begin execution
$Kitchen=Build-Kitchen
Stop-SophosServices
Suspend-BitlockerEncx
Write-Output "`nSearching for installed Sophos Apps..."
Initialize-OrderedSophosMSIsForUninstall $(Get-InstalledSophosMSI)
Remove-SED
Invoke-SophosZap
