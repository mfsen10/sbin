<#
Invoke-MSIhandler.ps1
.SYNOPSIS
Intended to take provided custom params for a given MSI and perform an uninstall, in-place upgrade/reinstall, or rip-and-replace upgrade. 
.DESCRIPTION
@author: MF@CFI~20230719
#>
#requires -runasadministrator

#### fn declarations

Function Confirm-Program_Installed([string]$programName) 
    {
        $wmi_check = (Get-CimInstance -Class "Win32_Product" -Filter "Name LIKE '$programName%'").name.length -gt 0
        return $wmi_check;
    }

Function Remove-MSIPkg 
    {
        Param ($MarkedAppGUID)
        $ChamberFiredTstamp = "$(get-date -format 'yyyyMMdd-HHmmss')"
        #Write-Output "    DEBUG: MSIexec nixing $markedappguid at $ChamberFiredTstamp "
        #TODO: execute uninstall
        $MSIexec = "$Env:windir\system32\msiexec.exe"
        #Set-Location -Path $Kitchen
        $NamedLogfile = "UninstLog-$MarkedAppGUID-$ChamberFiredTstamp.txt"
        $arglist = "/X `"$MarkedAppGUID`" /qn /norestart /L*v `"$Kitchen\$NamedLogfile`""
        Write-Output "`n    Removing via $MSIexec $arglist"
        $msiserveris = $(get-service msiserver).status
        if  ($msiserveris -ne "Running")
            {
                start-service msiserver
            }

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
                        Start-Process -FilePath "$env:windir\system32\MSG.exe" -Args "* $FriendlyName changes have been made and require a reboot - Please reboot this machine as soon as possible to avoid performance issues`n`nThank you - $FriendlyName Upgrade Administrators"
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

Function Get-InstalledMSIdata
    {
        Write-Output "Searching for installed Sophos Apps..."
        $instSophApps = Get-CimInstance -Class "win32_product" -Filter "Name = '$RegisteredAppDisplayNames'"
        #$instSophApps = Get-CimInstance -property Name,IdentifyingNumber -Class "win32_product" -Filter "Name LIKE 'Sophos%' AND NOT Name='Sophos Endpoint Defense' AND NOT Name LIKE '%safeguard%'"
        $AppCount = $instSophApps.Name.count
        if ($appcount -gt 0)
            {
                Write-Warning "    Found $AppCount relevant MSI modules installed, beginning removals"
            }
        return $instSophApps
    }

Function Initialize-OrderedMSIsetForUninstall
    {
        Param ($InstalledMSIarray)
        if($InstalledMSIarray.name.count -gt 0)
            {
                $removalctr = 0;
                Write-Output "    $friendlyName installs found."
                foreach ($NamedAppForRemoval in $RegisteredAppDisplayNames)
                    {
                        Write-output "`nStep $removalctr. $NamedAppForRemoval to be removed"
                        $rmStepping = 0;
                        foreach($MSIdatasheet in $InstalledMSIarray)
                            {
                                $InstalledMSIname = $MSIdatasheet.name
                                if ($InstalledMSIname -like "$NamedAppForRemoval*")
                                    {
                                        $MSIguid=$MSIdatasheet.IdentifyingNumber
                                        Write-Output "    $InstalledMSIname is installed, matches current place in ordered removal. Removing $MSIguid"
                                        Write-Debug "($removalctr found in $rmStepping.)" 
                                        Invoke-MSIrmEngine $MSIdatasheet
                                    }else{
                                        Write-Debug "    $NamedAppForRemoval not in slot, skipping."
                                    }
                                $rmStepping++;
                            }
                        $removalctr++;
                    }
            }else{
                Write-Output "No Further $FriendlyName MSI's found"
            }
    }

Function Invoke-WriteLog ([string]$LogString) 
    {
        $Logfile = ".\$FriendlyName-$env:computername.log"
        $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
        $LogMessage = "$Stamp $LogString"
        Add-content $LogFile -value $LogMessage
        Start-Transcript -Append $Logfile
    }

Function Build-Kitchen 
    {
        $NamedKitchen = "$FriendlyName"
        $KitchenPath = "$Env:SystemDrive\Temp\$NamedKitchen"
        #$logpathexists=(Get-Item $KitchenPath).name -gt 0;
        if (!(Test-Path $KitchenPath))
        {
            Write-Output "Kitchen not found, building $KitchenPath"
            if (!(Test-Path "\temp")) {New-Item -Path "\Temp" -ItemType Directory }
            New-Item -Path "$KitchenPath" -ItemType Directory 
        }
        Set-Location -Path $KitchenPath
        return $KitchenPath;
    }

Function Get-Platform
    {
        $prodName = (get-itemproperty "HKLM:\\SOFTWARE\Microsoft\Windows NT\CurrentVersion\").ProductName
        if ($prodname -like "*server*") 
            {
                $onWorkstation = $FALSE;
                Write-Output "Detected $prodName as Server platform, disabling workstation tasks from queue"
            }else{
                $OnWorkstation = $TRUE;
                Write-Output "Detected $prodName as Workstation platform, enabling workstation tasks to queue"
            }
        return $onWorkstation
    }

Function Test-LocalPkg #([string]$payload) 
    {
        Param ($payload)
        if(Test-Path $payload)
            {
                if ((Get-FileHash -Algorithm 'SHA256' -Path $payload).Hash -eq $payloadSHA2) 
                    {
                        Write-Output "Installer package delivered and hashed successfully, continuing installation"
                        return $TRUE; 
                    }else{
                        Write-Output "Installer package hash mismatch - failed download/file corruption/tampering - exiting"
                        Stop-Transcript
                        exit 4;
                    }
            }else{
                Write-Output "Installer package not found at configured location '$payload' - exiting"
                Stop-Transcript
                exit 3;
            }
    }

Function Install-MSIpkg #([string]$payload)
    {
        Param ($payload)
        $namedPL = Split-path -leaf $payload 
        $ChamberFiredTstamp = "$(get-date -format 'yyyyMMdd-HHmmss')"
        #Write-Debug "    DEBUG: MSIexec nixing $markedappguid at $ChamberFiredTstamp "
        $NamedLogfile = "InstLog-$namedPL-$ChamberFiredTstamp.txt"
        $MSIexec = "$Env:windir\system32\msiexec.exe"
        $arglist = "/i `"$payload`" /qn /norestart /L*v `"$Kitchen\$NamedLogfile`" $payloadArgs"
        Write-Output "`n    Installing via $MSIexec $arglist"
        $msiserveris = $(get-service msiserver).status
        while (!($msiserveris -eq "Running"))
            {
                start-service msiserver;start-sleep 2; 
            }

        $doInstall = Start-Process -FilePath "$MSIexec" -ArgumentList $arglist -Wait -PassThru

        # while ($doInstall.HasExited -eq $false )
        #     {
        #         Write-Output "Waiting for $process..."
        #         Start-Sleep -s 1
        #     }

        $exitCode = $doInstall.ExitCode
        if ($exitCode -ne 0 -and $exitcode -ne 3010)
            {
                Write-Host "    MSI exit code $exitCode" -ForegroundColor red
                $logpath = "$Kitchen\$NamedLogfile"
                Write-Output "    Get MSIexec Log Here:    `n$logPath`n"
                $failSrc = Get-Content -Path $logPath |select-string "error"
                Write-Error "Error Log Dump:`n$failSrc"
                Stop-Transcript
                #$MillerTime = 9990000+$exitCode
                exit $ExitCode; 
            }else{
                $appInstallRegistered = Confirm-Program_Installed $RegisteredAppDisplayNames
                Write-Output "    INSTALLED MSI $FriendlyName! Exit status $exitCode App Registration Check returns $appInstallRegistered "
                if ($exitCode -eq 3010)
                    {
                        Write-Output "Last App reported Reboot Required, throwing userland GUID reboot request"
                        #todo: figure out a method of sleeping on msg prompt so SED removal can complete before user bails the machine out of it.  this sleep works but might open a cmd window for timeout phase and the escaped linebreaks don't work.
                        #Start-Process -FilePath "$env:windir\system32\cmd.exe" -Args "/C timeout 60 && msg.exe * Sophos removal has completed and requires a reboot - Please reboot this machine as soon as possible to avoid performance issues\`n\`nThank you - Microsoft Defender Deployment Administrator"
                        Start-Process -FilePath "$env:windir\system32\MSG.exe" -Args "* $FriendlyName changes have been made and require a reboot - Please reboot this machine as soon as possible to avoid performance issues`n`nThank you - $FriendlyName Upgrade Administrators"
                    }

            }
    }

#endregion functions

#region meta declarations
$upgradePath = 2
switch ($upgradePath)
{
    0 {$upgradePathName = "Uninstall"}
    1 {$upgradePathName = "Install/Upgrade"}
    2 {$upgradePathName = "Uninstall/Upgrade"}
    default {Write-Output "Invalid upgrade path set, cannot continue";stop-transcript;exit 6}
}
$RmAttemptCounter = 0
$removalctr = 0
$rmStepping = 0
#$DriveLetter = $env:SystemDrive
Clear-Host
$ephemeralDropPath = (Get-Location).Path
#endregion meta declarations
#region app-specific declarations
$FriendlyName = "Bitglass"
$RegisteredAppDisplayNames = "Bitglass SmartEdge Autoinstaller"
$TargetAppDisplayVersion = "1.7.0.230330-554"
$ServiceNames = 'bgAutoinstaller','bgSmartEdge','bitglass_seproxy','sedns'
$targetBGdllVersion = "1.2.2"
$PayloadName = "Bitglass-SmartEdge-Autoinstaller-x64-1.2.2.msi"
$payloadSHA2 = "8389E469D54CE49F4EE7DEBB353640B640DA015823C3DECFD24B7B98A18B33BD"
$payloadArgs = ""
$payloadPath = "$ephemeralDropPath\$PayloadName"
### dynamic variables that will change in runtime, must recall.
#$CurrentAppDisplayVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\XXXXXXXXXXXXX\" -name DisplayVersion).DisplayVersion
$bgconfArr = Get-ItemPropertyValue "HKLM:\SOFTWARE\Bitglass\" -name "last-config" -ErrorAction SilentlyContinue|ConvertFrom-Json
$bgconf = $bgconfArr.configuration 
$activeBGuser = $bgconf.assigned_username
$CurrentAppDisplayVersion = Get-ItemPropertyValue "HKLM:\SOFTWARE\Bitglass\" -name 'installed_version' -ErrorAction SilentlyContinue
$currentBGdllVersion = Get-ItemPropertyValue "HKLM:\SOFTWARE\Bitglass\" -name "dll_version" -ErrorAction SilentlyContinue
$UpgradeComplete = $CurrentAppDisplayVersion -eq $TargetAppDisplayVersion
$DLLVersionMatches = $currentBGdllVersion -eq $targetBGdllVersion
$installExists = (($CurrentAppDisplayVersion.length -gt 0) -and ($NULL -ne $CurrentAppDisplayVersion))
#endregion app-specific declarations

#region execute
Write-Host "******************************" -ForegroundColor Magenta
Write-Host "** $FriendlyName $upgradePathName script. " -ForegroundColor Magenta
Write-Host "******************************`n`n`n" -ForegroundColor Magenta
$Kitchen=Build-Kitchen
Write-Output "Working from $Kitchen"
Invoke-WriteLog ("`n`nBeginning $FriendlyName Maintenance")
$onWorkstation=Get-Platform
if ($onWorkstation)
    {
        Write-Output "`nSearching for installed $FriendlyName modules: $RegisteredAppDisplayNames"
        $deliverySuccessful = Test-LocalPkg $payloadPath
        #TODO : write pub/semi-pub/private latest MSI fetch function. should definitely do remote call method prior to removals as to confirm MSI downlaod completed 
        # so it is ready to rip into install ASAP.
        if ($deliverySuccessful)
            {
                if ($upgradePath -in 0,2) 
                    {
                        if ($installExists)
                            {
                                Write-Output "Found $RegisteredAppDisplayNames ver $CurrentAppDisplayVersion is installed for $activeBGuser - performing removal"
                                Initialize-OrderedMSIsetForUninstall $(Get-InstalledMSIdata)
                            }else{
                                Write-Output "Removal was requested, but no existing install found - skipping"
                            }
                    }
                if ($upgradePath -in 1,2)
                    {
                        Install-MSIpkg $payloadPath
                        $CurrentAppDisplayVersion = Get-ItemPropertyValue "HKLM:\SOFTWARE\Bitglass\" -name 'installed_version' -ErrorAction SilentlyContinue
                        $currentBGdllVersion = Get-ItemPropertyValue "HKLM:\SOFTWARE\Bitglass\" -name "dll_version" -ErrorAction SilentlyContinue
                        $UpgradeComplete = $CurrentAppDisplayVersion -eq $TargetAppDisplayVersion
                        $DLLVersionMatches = $currentBGdllVersion -eq $targetBGdllVersion
                        Write-Output "Upgrade Status returns $UpgradeComplete (found $CurrentAppDisplayVersion.exe)"
                        
                        if ($ServiceNames.length -gt 0)
                            {
                                Write-output "Giving service(s) $ServiceNames a chance to start before checking status..."; Start-sleep 10;
                                Get-Service $ServiceNames|Format-Table -a
                            }
                    }
            }else{
                Write-Output "Pkg delivery check failed but did not error out yet!?"
                Stop-Transcript
                exit 5;
            }
        if (!$DLLVersionMatches)
            {
                if ($currentBGdllVersion.length -gt 0)
                    {
                        Write-Warning "Review installation - $FriendlyName reports mismatched DLL version $currentBGdllVersion for app verison $CurrentAppDisplayVersion. Should be $targetBGdllVersion"
                    }
            }
    }else{
        Write-Output "Running on server - will remove $FriendlyName if existent - Servers not spec'ed for $FriendlyName use as of Q3-23"
        Initialize-OrderedMSIsetForUninstall $(Get-InstalledMSIdata)
    }
Stop-Transcript
exit 0;
#endregion execute
<#
DLL ver | Agent ver
1.1.32.0    1.6.1
1.1.36.0    1.6.3
1.1.39.0    1.6.5
1.2.2.0     1.7.0

Manual removal process from 1.6.5/1.7.0 era, per working session with Forcepoint 2023 Jul 25
Delete:
Computer\HKEY_LOCAL_MACHINE\Software\Bitglass
Computer\HKEY_LOCAL_MACHINE\Software\WOW6432Node\Bitglass
Computer\HKEY_LOCAL_MACHINE\Software\Classes\Installer\Products\xxxxxxxxxxx (search product name: Bitglass SmartEdge Autoinstaller. happend to be 3EFE94E12214B214FAD36868A5490C41 for me.)

Stop services -> stop the 4 Bitglass services (bgAutoinstaller,bgSmartEdge,bitglass_seproxy,sedns)

Attempt Control Panel Add/Remove Programs -> Uninstall "Bitglass SmartEdge Autoinstaller"
If that doesn't work, delete: C:\Program Files\Bitglass


C:\program files\Bitglass\
C:\ProgramData\Bitglass\
C:\windows\system32\config\systemprofile\AppData\Local\Bitglass\

List of regkey parent branches for leaves containing bitglass/autoinstallersvc.exe/bgautoinstaller - remaining after failed 170-122 removal
!! NOTE if looking for yourself, and see references to Defender or Intune, LEAVE THEM BE! MDE exclusions and intune pkg deployments. 
Computer\HKEY_CLASSES_ROOT\Installer\Products\3EFE94E12214B214FAD36868A5490C41
Computer\HKEY_CURRENT_USER\Bitglass
Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Bitglass
Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\Products\3EFE94E12214B214FAD36868A5490C41
Computer\HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Bitglass
Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components\6D41D4C564211414780D04B19282DD9A
Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components\7CE7560E538104C4C98EBDAB71C9A547
Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components\85D78B66B1DD1FC4D9E12F85E977589C
Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components\9874A9C200B519F54945A487C2C25F22
Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components\A7B89540116281C44ABA6DBEF4D17C63
Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components\B4D95E1A4ED1A074689F83A340FFC84D
Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\3EFE94E12214B214FAD36868A5490C41
Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{1E49EFE3-4122-412B-AF3D-86865A94C014}
Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\seproxy.exe
Computer\HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Cryptography\Services\bitglass_seproxy
Computer\HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Internet Settings
Computer\HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EventLog\Application\bitglass_seproxy
Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bgAutoinstaller
Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Application\bitglass_seproxy
(Get-item HKLM:\software\Microsoft\Windows\CurrentVersion\Installer\Folders\).property|select-string bitglass


Stop-Service 'bgAutoinstaller','bgSmartEdge','bitglass_seproxy','sedns'  -ErrorAction silentlycontinue
Remove-Item -Recurse -Force 'C:\program files\Bitglass\' -ErrorAction silentlycontinue
Remove-Item -Recurse -Force 'C:\ProgramData\Bitglass\' -ErrorAction silentlycontinue
Remove-Item -Recurse -Force 'C:\windows\system32\config\systemprofile\AppData\Local\Bitglass\' -ErrorAction silentlycontinue

New-PSDrive -Name "HKCR" -PSProvider Registry -Root "HKEY_CLASSES_ROOT" -ErrorAction silentlycontinue
Remove-Item -Recurse 'HKCR:\Installer\Products\3EFE94E12214B214FAD36868A5490C41' -ErrorAction silentlycontinue
Remove-PSDrive HKCR -ErrorAction silentlycontinue

Remove-Item -Recurse -Force 'HKCU:\Bitglass' -ErrorAction silentlycontinue
Remove-Item -Recurse -Force 'HKLM:\SOFTWARE\Bitglass' -ErrorAction silentlycontinue
Remove-Item -Recurse -Force 'HKLM:\SOFTWARE\Classes\Installer\Products\3EFE94E12214B214FAD36868A5490C41' -ErrorAction silentlycontinue
Remove-Item -Recurse -Force 'HKLM:\SOFTWARE\WOW6432Node\Bitglass' -ErrorAction silentlycontinue
Remove-Item -Recurse -Force 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components\6D41D4C564211414780D04B19282DD9A' -ErrorAction silentlycontinue
Remove-Item -Recurse -Force 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components\7CE7560E538104C4C98EBDAB71C9A547' -ErrorAction silentlycontinue
Remove-Item -Recurse -Force 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components\85D78B66B1DD1FC4D9E12F85E977589C' -ErrorAction silentlycontinue
Remove-Item -Recurse -Force 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components\9874A9C200B519F54945A487C2C25F22' -ErrorAction silentlycontinue
Remove-Item -Recurse -Force 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components\A7B89540116281C44ABA6DBEF4D17C63' -ErrorAction silentlycontinue
Remove-Item -Recurse -Force 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components\B4D95E1A4ED1A074689F83A340FFC84D' -ErrorAction silentlycontinue
Remove-Item -Recurse -Force 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\3EFE94E12214B214FAD36868A5490C41' -ErrorAction silentlycontinue
Remove-Item -Recurse -Force 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{1E49EFE3-4122-412B-AF3D-86865A94C014}' -ErrorAction silentlycontinue
Remove-Item -Recurse -Force 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\seproxy.exe' -ErrorAction silentlycontinue
Remove-Item -Recurse -Force 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Cryptography\Services\bitglass_seproxy' -ErrorAction silentlycontinue
Remove-Item -Recurse -Force 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction silentlycontinue
Remove-Item -Recurse -Force 'HKLM:\SYSTEM\ControlSet001\Services\EventLog\Application\bitglass_seproxy' -ErrorAction silentlycontinue
Remove-Item -Recurse -Force 'HKLM:\SYSTEM\CurrentControlSet\Services\bgAutoinstaller' -ErrorAction silentlycontinue
Remove-Item -Recurse -Force 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\bitglass_seproxy' -ErrorAction silentlycontinue

Remove-ItemProperty -Force -Path 'HKLM:\software\Microsoft\Windows\CurrentVersion\Installer\Folders\' -Name 'C:\Program Files\Bitglass\SmartEdge Autoinstaller\logs\'
Remove-ItemProperty -Force -Path 'HKLM:\software\Microsoft\Windows\CurrentVersion\Installer\Folders\' -Name 'C:\Program Files\Bitglass\SmartEdge Autoinstaller\'
Remove-ItemProperty -Force -Path 'HKLM:\software\Microsoft\Windows\CurrentVersion\Installer\Folders\' -Name 'C:\Program Files\Bitglass\'
Remove-ItemProperty -Force -Path 'HKLM:\software\Microsoft\Windows\CurrentVersion\Installer\Folders\' -Name 'C:\ProgramData\Bitglass\Shared\'
Remove-ItemProperty -Force -Path 'HKLM:\software\Microsoft\Windows\CurrentVersion\Installer\Folders\' -Name 'C:\ProgramData\Bitglass\'
Set-ItemProperty -force -path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Internet Settings' -name 'AutoConfigURL' -value ''
set-itemProperty HKLM:\SYSTEM\ControlSet001\Services\NlaSvc\Parameters\Internet\ManualProxies -name '(default)' -value ''

## IP Helper service maintains proxy helper cache here with all the autoconfigURL's used Computer\HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\iphlpsvc\Parameters\ProxyMgr\

gotta reboot after this if anything in HKLM:\System was modified. 



Get-CIMinstance
Name                  : Bitglass SmartEdge Autoinstaller
Version               : 1.2.2
InstallState          : 5
Caption               : Bitglass SmartEdge Autoinstaller
Description           : Bitglass SmartEdge Autoinstaller
ElementName           :
InstanceID            :
IdentifyingNumber     : {1E49EFE3-4122-412B-AF3D-86865A94C014}
SKUNumber             :
Vendor                : Bitglass, Inc.
WarrantyDuration      :
WarrantyStartDate     :
AssignmentType        : 1
HelpLink              : www.bitglass.com
HelpTelephone         :
InstallDate           : 20230721
InstallDate2          :
InstallLocation       :
InstallSource         : C:\Temp\BitGlass\
Language              : 1033
LocalPackage          : C:\windows\Installer\80d2b9d.msi
PackageCache          : C:\windows\Installer\80d2b9d.msi
PackageCode           : {5E03A5D6-E0D3-4F94-8A10-0D79B8241F9C}
PackageName           : Bitglass-SmartEdge-Autoinstaller-x64-1.2.2.msi
ProductID             :
RegCompany            :
RegOwner              :
Transforms            :
URLInfoAbout          :
URLUpdateInfo         :
WordCount             : 0
PSComputerName        :
CimClass              : root/cimv2:Win32_Product
CimInstanceProperties : {Caption, Description, ElementName, InstanceID…}
CimSystemProperties   : Microsoft.Management.Infrastructure.CimSystemProperties
#>
