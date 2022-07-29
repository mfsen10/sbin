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

#########################################################################################################
### Housekeeping
Clear-Host
$RmAttemptCounter = 0
$removalctr = 0
$rmStepping = 0
#########################################################################################################
#### Welcome banner
Write-Host "******************************" -ForegroundColor Magenta
Write-Host "** Sophos uninstall script. **" -ForegroundColor Magenta
Write-Host "******************************`n`n`n" -ForegroundColor Magenta

Function Get-Check_Program_Installed( $programName ) 
    {
        $wmi_check = (Get-WMIObject -Query "SELECT * FROM Win32_Product Where Name Like '$programName%'").name.length -gt 0
        return $wmi_check;
    }

Function Remove-Pkg 
    {
        Param ($MarkedAppGUID)
        $ChamberFiredTstamp = get-date -format 'yyyyMMdd-HHMMssZuluK'
        #TODO: execute uninstall
        Start-Process "msiexec.exe" -arg "/X "$MarkedAppGUID" /qn REBOOT=SUPPRESS /norestart /L*v %windir%\Temp\Uninst$MarkedAppGUID_Log-$ChamberFiredTstamp.txt" -Wait
        Write-Debug "    DEBUG: Merking $markedappguid at $ChamberFiredTstamp "
    }

#### Glorified MSI Package removal function wrapper. Most Sophos modules are MSI packages. 
Function Remove-Sophos
    {
        Param ($Application)
        Write-Output "    Attempting to uninstall $($Application.Name)"
            try
                {
                    #Uninstall-Package $Application.Name
                    # ah ah ahhhh can't use non-native packagemgmt module...
                    $InChamberAppGUID = $Application.IdentifyingNumber
                    $InChamberAppName = $Application.Name
                    Remove-Pkg $InChamberAppGUID
                    $RmAttemptCounter = 1
                    
                    #$Installed = Get-Package | Where-Object {$_.Name -like $Application.Name}
                    # ah ah ahhhh can't use non-native packagemgmt module...
                    $StillInstalled = $TRUE
                    #$StillInstalled = (Get-WmiObject win32_product -filter {IdentifyingNumber = "$InChamberAppGUID"}).name
                    #$StillInstalled = Get-WmiObject win32_product -filter {name like "$InChamberAppName"}
                    $StillInstalled = Get-Check_Program_Installed $InChamberAppName
                    Write-Output "    Confirming that $InChamberAppName ($inchamberappguid) is uninstalled via name (is-installed evaluated: $StillInstalled)"
                    While ($StillInstalled -and $RmAttemptCounter -lt 4)
                        {
                            Write-Output "    $InChamberAppName was not uninstalled, trying again... ($RmAttemptCounter)" 
                            Remove-Pkg $InChamberAppGUID
                            $RmAttemptCounter++
                        }

                    If ($StillInstalled)
                        {
                            Write-Error "`n`nERROR: Unable to uninstall $InChamberAppName after $RmAttemptCounter times"
                            exit 1;
                        }

                    Else
                        {
                            Write-Output "Successfully removed $InChamberAppName"
                            $RmAttemptCounter = 0
                        }
                }
            catch
                {
                    Write-Error "Error: Failed to remove $InChamberAppName"
                }
    } # End of the function

Function Remove-SED 
    {
        #########################################################################################################
        <### Endpoint Defense isn't maintained by MSI so needs to handles separately, and last - per Sophos doc.
        HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\Sophos Endpoint Defense
            DisplayName    REG_SZ    Sophos Endpoint Defense
            "C:\Program Files\Sophos\Endpoint Defense\SEDuninstall.exe"
        #>     
        Write-Output "`nAttempting to uninstall Sophos Endpoint Defense"
        $SEDinstalled = Get-Check_Program_Installed "Sophos Endpoint Defense"
        if ($null -ne $SEDinstalled)
        {
            try {
                #TODO: Execute uninstall
                #start-process "C:\Program Files\Sophos\Endpoint Defense\SEDuninstall.exe"
                #Write-Output "Successfully removed Sophos Endpoint Defense"
                Write-Debug "DEBUG: Would be removing SED at this time. Maybe look at flags available to ensure silent noreboot`n"
            }
            catch {
                Write-Error "Error: Failed to remove Sophos Endpoint Defense - attempting Zap!!!!"
                #invoke-webrequest https://download.sophos.com/tools/SophosZap.exe -outfile "%windir%\temp\SophosZap.exe"
                #start-process "%windir%\temp\SophosZap.exe" -arg "--confirm" -Wait
            }
        }else{
            Write-Output "`nNo Sophos apps found as of $(Get-Date)"
            exit 0;
        }
}


#########################################################################################################
#### Stop potentially disruptive service 
Function Stop-SophosServices
    {
        Write-Output "Attempting to halt Sophos AutoUpdate Service and set bitlocker suspension for two reboots"
        try
            {
                Write-Debug "DEBUG: would be stopping $((Get-Service -Name "Sophos AutoUpdate Service").Displayname)"
                #Stop-Service -Name "Sophos AutoUpdate Service" -PassThru
            }
        catch
            {
                Write-Error "Unable to stop the AutoUpdate Service"
            }
        ##Suspend Bitlocker to prevent lock - we're modifying kernel modules with the AV stuff which probably will trip recovery. 
            try{
                Write-Debug "DEBUG: would be suspending bitlocker now"
                #Suspend-BitLocker -MountPoint "C:" -RebootCount 2
            }
            catch
            {
                Write-Error "Unable to suspend Bitlocker"
            }
    }

#########################################################################################################
#### For each ordered app, find the matching installed app via wildcard for versioned naming conventions, and execute removal.
Function Set-OrderedSophosMSIsForUninstall
{
    if($null -eq $instSophApps) 
        {
        Remove-SED   
        }else{
            $removalctr = 0;
            foreach ($NamedSophappToRm in $NamedSophAppRmOrder)
                {
                    Write-output "`nStep $removalctr. $NamedSophappToRm to be removed"
                    $rmStepping =0;
                    foreach($FoundSophAppBlob in $instSophApps)
                        {
                            $NamedInstApp = $FoundSophAppBlob.name
                            #write-output "      Matches $NamedInstApp ?"
                            if ($NamedInstApp -like "$NamedSophAppToRm*")
                                {
                                    $removalappGuid=$FoundSophAppBlob.IdentifyingNumber
                                    Write-Output "    $NamedInstApp is installed, matches current place in ordered removal. Removing $removalappGuid ($removalctr found in $rmStepping.)" 
                                    Remove-Sophos $FoundSophAppBlob
                                }else{
                                    Write-Debug "    $NamedSophappToRm not in slot, skipping."
                                }
                            $rmStepping++;
                        }
                    $removalctr++;
                }
        }
}
#########################################################################################################
#### var defs
# Construct two arrays, one of known app list as the ordering principle, and one of the discovered apps on machine as the environment to apply ordered removal to.
# Official uninstall order, count 14, array of 13)

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
"Sophos Endpoint Defense",
"Sophos SafeGuard Client Configuration",
"Sophos SafeGuard Client",
"Sophos SafeGuard Preinstall"


Write-Output "Gathering installed Sophos Apps"
# note we'll be removing the exe-based installer after all this MSI package removal.
$instSophApps = Get-WmiObject win32_product -filter {name like "%Sophos%" and not name like "Sophos Endpoint Defense"}


#begin execution
Stop-SophosServices
Set-OrderedSophosMSIsForUninstall
