#Must be run in admin shell with line-of-sight to endpoints and Azure/INET. 
#requires -runasadministrator
#only needs run once per machine (maybe user profile) but no harm if it's attempted to run again. 
#Install-Module AzureAD -Scope AllUsers
#pops modern auth window asking for azure portal creds, use the account that has Cloud Admin PIM
#Connect-AzureAD


$machineNameList = "mach1","machine2"

foreach ($machine in $machineNameList)
{
    #azureAD facing.
    # get list of devices for hostname
    $objIDArray = (Get-AzureADDevice -Filter "(DisplayName eq '$machine')")
    # reorder list of devices by lastActive ascending
    $regDateOrderedObjArray = $objIDArray|sort-object -property 'ApproximateLastLogonTimeStamp'
    #extract objectids in lastActive Order 
    $ObjIDsforMachineName = $regDateOrderedObjArray.objectID
    #count them
    $objCount = $ObjIDsforMachineName.count
    #don't start scrubbing if only one left.
    if ($objCount -ne 1 )
    {
        foreach ($objectID in $ObjIDsforMachineName)
        # scrub for multirecords
        {
            while ($objcount -ne 1)
            #only while there are more than one.
            {
                Remove-AzureADDevice -ObjectId $objectID
                #$machineDispName = (Get-AzureADDevice -ObjectId $objectID).displayname
                Write-Host "Deleted object $objectid"
                #recount after removal
                $objIDArray = (Get-AzureADDevice -Filter "(DisplayName eq '$machine')")
                # reorder list of devices by lastActive ascending
                $regDateOrderedObjArray = $objIDArray|sort-object -property 'ApproximateLastLogonTimeStamp'
                #extract objectids in lastActive Order 
                $ObjIDsforMachineName = $regDateOrderedObjArray.objectID
                #count them
                $objCount = $ObjIDsforMachineName.count
                $objectID=$ObjIDsforMachineName[0]
            }
        }
    }
    #endpoint-facing rejoin. captures a user list in case we want to vet username/hostname
#    Write-host "`n`nPreparing to disjoin/rejoin $machine from/to AzureAD.`n`n"
#    set-service -name winrm -status running -computername $machine
#    Write-host "`n`nCollecting list of current console user sessions. Just an FYI who we're working with.`n`n"
#    Invoke-Command -ComputerName $machine -Scriptblock {qwinsta;hostname;}
#    Write-Host "`n`nForcing an attempt to rejoin $machine. May not complete entirely, but should still resolve user experience issues.`n`n"
#    Invoke-Command -ComputerName $machine -Scriptblock {dsregcmd /debug /join;}
#    Write-Warning "`n`n`n`nThis completes the disjoin/rejoin process for $machine, moving along if others are defined: `n`n`n`n"
}
