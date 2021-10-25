<#
	.SYNOPSIS
		Set-Office365C2RChannel modifies Office 365 Click to Run Update Channel

	.DESCRIPTION
		Modifies Office 365 Click to Run Update Channel. Takes channel option from CLI or requests it in runtime. 

	.PARAMETER SetChannel
			Specifies channel option to set and update to.

			1 : Monthly Enterprise Channel (THe new _ACTUAL_ monthlies)
			2 : Current Channel (Preview) (Prev/AKA, Monthly Channel Targeted/InsiderSlow)
			3 : Current Channel (Prev/AKA, Monthly Channel)
			4 : Beta Channel (Prev/AKA, Insider/Fast)
			5 : Semi-Annual Enterprise Channel (Prev/AKA, Preview) (Semi-Annual Channel Targeted)
			6 : Semi-Annual Enterprise Channel (Prev/AKA, Semi-Annual Channel)

	           PropertyType					string
	           Required?                    false
	           Position?                    0
	           Default value				0
	           Accept pipeline input?       false
	           Accept wildcard characters?

	.LINK
	Gr33tz: 
	The Wayback project (technet why you delete doc? T__T) https://web.archive.org/web/20190420045307/https://blogs.technet.microsoft.com/odsupport/2014/03/03/the-new-update-now-feature-for-office-2013-click-to-run-for-office365-and-its-associated-command-line-and-switches/
	@ComDannyda : https://dannyda.com/2020/05/06/how-to-switch-change-between-monthly-channel-and-semi-annual-channel-for-office-365-office-2019-how-to-switch-update-channel-for-office-365-office-2019/
	PatrickTeas@Comsense:https://support.comsenseinc.com/hc/en-us/articles/360006783014-How-to-Determine-and-Change-your-Office-365-Update-Channel
	DaveGunther@MS:https://techcommunity.microsoft.com/t5/office-365-blog/understanding-office-365-proplus-updates-for-it-pros-cdn-vs-sccm/ba-p/795728 
	The FMS Dev Team: https://www.fmsinc.com/microsoft-office/change-office-365-channel.html
	- The PowersHELL Team@MS for producing a functional shell
	- Countless SOFlowers
	Author: mf@GSD, 20211021
#>
#$SetChannel=$args[0]
param([string]$SetChannel=0)

function Show-Menu{
    Write-host -ForegroundColor green ""
    write-host -ForegroundColor green "========================================================================"
    Write-Host -ForegroundColor green "===============    Set Office365 Click to Run Channel    ==============="
    Write-Host -ForegroundColor green "==============                 By: GSDFin                 =============="
    write-host -ForegroundColor green "========================================================================"
	write-host -foregroundColor green "           __        __       __        __       __        __           "
	write-host -foregroundColor green "          /\ \      / /\     /\ \      / /\     /\ \      / /\          "
	write-host -foregroundColor green "         / /\ \    / /\ \   / /\ \    / /\ \   / /\ \    / /\ \         "
	write-host -foregroundColor green "        / /__\ \__/_/__\ \ / /__\ \__/_/__\ \ / /__\ \__/_/__\ \        "
	write-host -foregroundColor green "        \/____\ \_______\/ \/____\ \_______\/ \/____\ \_______\/        "
	write-host -foregroundColor green "                \/ /               \/ /               \/ /              "
	write-host -foregroundColor green "               / /\               / /\               / /\               "
	write-host -foregroundColor green "              / /\ \             / /\ \             / /\ \              "
	write-host -foregroundColor green "             / /__\ \           / /__\ \           / /__\ \             "
	write-host -foregroundColor green "             \_____\/           \_____\/           \_____\/             "
	Write-Host -ForegroundColor green ""
	Write-Host -ForegroundColor green " 1 : Monthly Enterprise Channel (THe new _ACTUAL_ monthlies)"
	Write-Host -ForegroundColor green " 2 : Current Channel (Preview) (Prev/AKA, Monthly Channel Targeted/InsiderSlow)"
	Write-Host -ForegroundColor green " 3 : Current Channel (Prev/AKA, Monthly Channel)"
	Write-host -ForegroundColor green " 4 : Beta Channel (Prev/AKA, Insider/Fast)"
	Write-Host -ForegroundColor green " 5 : Semi-Annual Enterprise Channel (Prev/AKA, Preview) (Semi-Annual Channel Targeted)"
	Write-Host -ForegroundColor green " 6 : Semi-Annual Enterprise Channel (Prev/AKA, Semi-Annual Channel)"
	Write-Host -ForegroundColor green ""
	Write-Host -ForegroundColor green " Q : Press 'Q' to quit."
}

if (($SetChannel -eq "0") -or ($SetChannel -eq 0) -or ($SetChannel -eq $null)){
	Show-Menu
	$channel = Read-Host "Please make a selection"	
	$argwrite = "FALSE";
}else{
	$argwrite = "TRUE";
	$channel = $SetChannel;
}

switch ($channel) {
	'1' {

		Write-Host -ForegroundColor green 'Selected 1 - #Monthly Enterprise Channel (The new, ACTUAL monthlies)'
		$UpdateChannel = "MonthlyEnterprise"
		$ChannelCDN = "http://officecdn.microsoft.com/pr/55336b82-a18d-4dd6-b5f6-9e5095c314a6"
	} '2' {

		Write-Host -ForegroundColor green 'Selected 2 - #Current Channel (Preview) (Prev/AKA, Monthly Channel Targeted/InsiderSlow)'
		$UpdateChannel = "CurrentPreview"
		$ChannelCDN = "http://officecdn.microsoft.com/pr/64256afe-f5d9-4f86-8936-8840a6a4f5be"
	} '3' {

		Write-Host -ForegroundColor green 'Selected 3 - #Current Channel (Prev/AKA, Monthly Channel)'
		$UpdateChannel = "Current"
		$ChannelCDN = "http://officecdn.microsoft.com/pr/492350f6-3a01-4f97-b9c0-c7c6ddf67d60"
	} '4' {

		Write-Host -ForegroundColor green 'Selected 4 - #Beta Channel (Prev/AKA, Insider/Fast)'
		$UpdateChannel = "Beta"
		$ChannelCDN = "http://officecdn.microsoft.com/pr/5440fd1f-7ecb-4221-8110-145efaa6372f"
	} '5' {

		Write-Host -ForegroundColor green 'Selected 5 - #Semi-Annual Enterprise Channel (Prev/AKA, Preview) (Semi-Annual Channel Targeted)'
		$UpdateChannel = "SemiAnnualPreview"
		$ChannelCDN = "http://officecdn.microsoft.com/pr/b8f9b850-328d-4355-9145-c59439a0c4cf"
	} '6' {

		Write-Host -ForegroundColor green 'Selected 6 - Semi-Annual Enterprise Channel (Prev/AKA, Semi-Annual Channel)'
		$UpdateChannel = "SemiAnnual"
		$ChannelCDN = "http://officecdn.microsoft.com/pr/7ffbc6bf-bc32-4f92-8982-f9dd17fd3114"
	} 'q' {

		Write-Host -ForegroundColor yellow " Q : Pressed '$channel' to quit. Exit 1."
		exit 0;
	} 0 {

		Write-Host -ForegroundColor yellow " Q : Pressed "$channel" to quit. Exit 2."
		exit 0;
	} $null {

		Write-Host -ForegroundColor yellow " Q : Pressed "$channel" to quit. Exit 3."
		exit 0;
	} '0' {

		Write-Host -ForegroundColor yellow " Q : Pressed "$channel" to quit. Exit 4."
		exit 0;
	}
}

$validswitch ="1","2","3","4","5",'6'

if ($channel -in $validswitch) {
	#force null response to quit
	# query up the C2R installer config's value for null, which would imply it's not an active C2R instance, maybe MSI-based? 
	reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\Configuration /T REG_SZ /v CDNBaseUrl 
	if ( ('true' -eq $?) -and (0 -eq $LASTEXITCODE) ) {

		# pin the low-priority c2r install configuration to selected Channel  
		New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration  -Name CDNBaseUrl -PropertyType String -Value $ChannelCDN -force|Out-Null
		reg delete HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\Configuration /v UpdateUrl /f|Out-Null
		reg delete HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\Configuration /v UpdateToVersion /f|Out-Null
		reg delete HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\Updates /v UpdateToVersion /f|Out-Null
		reg delete HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Office\16.0\Common\OfficeUpdate\ /f|Out-Null
		
		# Pin C2R's hi-pri GPO reg's to ME channel
		New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\office\16.0\common\ -Name officeupdate -force |Out-Null
		New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate -Name updatebranch -PropertyType String -Value $UpdateChannel |Out-Null
		
		# Tell c2r to change channels however its undocumentedly ways work, and then go git gud
		start "$Env:CommonProgramFiles\microsoft shared\ClickToRun\OfficeC2RClient.exe" -ArgumentList "/changeSetting Channel=$channel"
		saps "$Env:CommonProgramFiles\microsoft shared\ClickToRun\OfficeC2RClient.exe" -ArgumentList "/update user displaylevel=false forceappshutdown=true"
		#start-process "$Env:CommonProgramFiles\microsoft shared\ClickToRun\OfficeC2RClient.exe" -ArgumentList "/update user"

		if ( ('true' -eq $?) -and (0 -eq $LASTEXITCODE) ) {
			write-host -ForegroundColor green "		###########################################################################################
			 PASS - UpdateChannel set to $Updatechannel, forcing background update now 
		###########################################################################################
			"
			sleep 2;
			exit 0;
		}else{
			write-host -ForegroundColor red  "		###########################################################################################
		     TEST - MUST PASS  posh operation success and win32app exiterr                
		###########################################################################################

		Some riffraff happened!
		SC: $SetChannel
		C : $channel
		UC: $UC
		CC: $ChannelCDN
		PX : $?
		WX : $LASTEXITCODE
		Exit 7.
		"
		sleep 5; 
		exit 2; 
		}
	}else{
		write-host -ForegroundColor magenta "		###########################################################################################
		Channel CDN was not set - invalid Office version or corrupted install        
		###########################################################################################
		"
		write-host -ForegroundColor red "
		ErrLev: $env:errorlevel, (poshOpsExit: $? ) win32exit:$LASTEXITCODE - Exit 6.
		"
		exit 2;
	}
}else{
		Write-Host -ForegroundColor yellow " Q : Pressed $channel to quit.
"
		exit 0;
}
#Batch Equivalent style
#::setlocal 
#::reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\Configuration\ /v CDNBaseUrl 
#::if %errorlevel%==0 (goto SwitchChannel) else (goto End) 
#:::SwitchChannel 
#::reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\Configuration /v CDNBaseUrl /t REG_SZ /d "http://officecdn.microsoft.com/pr/7ffbc6bf-bc32-4f92-8982-f9dd17fd3114" /f
#::reg delete HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\Configuration /v UpdateUrl /f 
#::reg delete HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\Configuration /v UpdateToVersion /f 
#::reg delete HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\Updates /v UpdateToVersion /f 
#::reg delete HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Office\16.0\Common\OfficeUpdate\ /f 
#::"%CommonProgramFiles%\microsoft shared\ClickToRun\OfficeC2RClient.exe" /update user 
#:::End 
#::Endlocal