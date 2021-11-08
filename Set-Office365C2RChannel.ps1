<#
	.SYNOPSIS
		Set-Office365C2RChannel modifies Office 365 Click to Run Update Channel

	.DESCRIPTION
		Modifies Office 365 Click to Run Update Channel, and then updates Office via the selected channel. Takes channel and update options from CLI or requests it in runtime.

	.PARAMETER SetChannel
		Specifies UpdateChannel to set and pull future updates from.

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
           Accept wildcard characters?	false
	.PARAMETER SetUpMeth
		Specifies Office update method if updating Office. 

		1 - Kills running office apps and provides document recovery options on re-open
		2 - Polite request to user for updating via userland GUI  
		0 - Just mod the channel, no update on this run (will update next according to the channel's cadence.)
           PropertyType					string
           Required?                    false
           Position?                    1
           Default value				0
           Accept pipeline input?       false
           Accept wildcard characters?	false

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
param(
	[string]$SetChannel,
	[string]$SetUpMeth
);

function Show-ChannelMenu{
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
$ValidChanOpt ="1","2","3","4","5","6","0"

function Show-UpdateMenu{
    Write-host -ForegroundColor green ""
    write-host -ForegroundColor green "========================================================================"
    Write-Host -ForegroundColor green "===============      Choose  Office365 Update Method     ==============="
    write-host -ForegroundColor green "========================================================================"
	Write-Host -ForegroundColor green " 1 - Force update and auto close apps (session resume/document recovery on re-open)"
	Write-Host -ForegroundColor green " 2 - Politely request userland update via C2R GUI"
	Write-Host -ForegroundColor green " 0 : Press '0' to quit after modifying UpdateChannel."
}
$validUpMethOpt ="1","2","0"

if (($SetChannel -notin $ValidChanOpt)){
	Show-ChannelMenu
	$CurrentChannel = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration -Name CDNBaseUrl
	switch ($CurrentChannel) {
		'http://officecdn.microsoft.com/pr/55336b82-a18d-4dd6-b5f6-9e5095c314a6' {

			$CurrentChannelName = "MonthlyEnterprise"
			Write-Host ""
			Write-Host -ForegroundColor magenta "Current ODT Channel set: $CurrentChannelName"
			Write-Host ""

		} 'http://officecdn.microsoft.com/pr/64256afe-f5d9-4f86-8936-8840a6a4f5be' {

			$CurrentChannelName = "CurrentPreview"
			Write-Host ""
			Write-Host -ForegroundColor magenta "Current ODT Channel set: $CurrentChannelName"
			Write-Host ""

		} 'http://officecdn.microsoft.com/pr/492350f6-3a01-4f97-b9c0-c7c6ddf67d60' {

			$CurrentChannelName = "Current"
			Write-Host ""
			Write-Host -ForegroundColor magenta "Current ODT Channel set: $CurrentChannelName"
			Write-Host ""

		} 'http://officecdn.microsoft.com/pr/5440fd1f-7ecb-4221-8110-145efaa6372f' {

			$CurrentChannelName = "Beta"
			Write-Host ""
			Write-Host -ForegroundColor magenta "Current ODT Channel set: $CurrentChannelName"
			Write-Host ""

		} 'http://officecdn.microsoft.com/pr/b8f9b850-328d-4355-9145-c59439a0c4cf' {

			$CurrentChannelName = "SemiAnnualPreview"
			Write-Host ""
			Write-Host -ForegroundColor magenta "Current ODT Channel set: $CurrentChannelName"
			Write-Host ""

		} 'http://officecdn.microsoft.com/pr/7ffbc6bf-bc32-4f92-8982-f9dd17fd3114' {

			$CurrentChannelName = "SemiAnnual"
			Write-Host ""
			Write-Host -ForegroundColor magenta "Current ODT Channel set: $CurrentChannelName"
			Write-Host ""

		}else{
			$CurrentChannelName = "UNKNOWN"
			Write-Host ""
			Write-Host -ForegroundColor red "Current ODT Channel set: $CurrentChannelName"
			Write-Host ""
		}
	}
	$CurrentGPOChannel = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate -Name UpdateBranch
	$validCGPOChan = "CurrentPreview","Current","Beta","SemiAnnualPreview","SemiAnnual","SemiAnnual", "MonthlyEnterprise"
	if (($CurrentGPOChannel -notin $validCGPOChan)){
		Write-Host -ForegroundColor red "Current GPO Channel set: UNKNOWN"
		Write-Host ""
	}else{
		Write-Host ""
		Write-Host -ForegroundColor magenta "Current GPO Channel set: $CurrentGPOChannel"
		Write-Host ""
	}

	$GUIchannel = Read-Host "Please make a selection"
	$Chanargwrite = "FALSE";
	$channel = $GUIchannel;
}else{
	$Chanargwrite = "TRUE";
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

		Write-Host -ForegroundColor yellow " Q : Pressed '$channel' to quit."
		exit 0;
	} 0 {

		Write-Host -ForegroundColor yellow " 0 : Selected "$channel" - skipping UpdateChannel modification"
		#exit 0;
	} $null {

		Write-Host -ForegroundColor yellow " Q : Pressed "$channel" to quit."
		exit 0;
	} '0' {

		Write-Host -ForegroundColor yellow " Q : Pressed "$channel" to quit."
		exit 0;
	}
}

if ($channel -in $ValidChanOpt) {
	#force null response to quit
	# query up the C2R installer config's value for null, which would imply it's not an active C2R instance, maybe MSI-based?
	reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\Configuration /T REG_SZ /v CDNBaseUrl
	if ( ('true' -eq $?) -and (0 -eq $LASTEXITCODE) ) {

		# pin the low-priority ODT install config to selected Channel  
		New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration  -Name CDNBaseUrl -PropertyType String -Value $ChannelCDN -force|Out-Null
		#set updates enabled from CDN in ODT app-level config
		New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration  -Name UpdatesEnabled -PropertyType String -Value "True" -force|Out-Null
		New-ItemProperty HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration -Name O365ProPlusRetail.MediaType  -PropertyType String -Value "CDN" -force|Out-Null 
		# undo ManageEngine DesktopCentral_Agent Mods 
		New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Scenario\UPDATE -Name BaseURL -PropertyType String -Value $ChannelCDN -force|Out-Null
		New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Scenario\UPDATE -Name UpdateURL -PropertyType String -Value $ChannelCDN -force|Out-Null
		New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Scenario\UPDATE -Name UpdatesEnabled -PropertyType String -Value "True" -force|Out-Null
		New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Scenario\UPDATE -Name MediaType -PropertyType String -Value "CDN" -force|Out-Null
		New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Scenario\UPDATE -Name SourceType -PropertyType String -Value "CDN" -force|Out-Null
		
		New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Scenario\CLIENTUPDATE -Name BaseURL -PropertyType String -Value $ChannelCDN -force|Out-Null
		New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Scenario\CLIENTUPDATE -Name UpdateURL -PropertyType String -Value $ChannelCDN -force|Out-Null
		New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Scenario\CLIENTUPDATE -Name UpdatesEnabled -PropertyType String -Value "True" -force|Out-Null
		New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Scenario\CLIENTUPDATE -Name MediaType -PropertyType String -Value "CDN" -force|Out-Null
		New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Scenario\CLIENTUPDATE -Name SourceType -PropertyType String -Value "CDN" -force|Out-Null

		New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Scenario\INSTALL -Name BaseURL -PropertyType String -Value $ChannelCDN -force|Out-Null
		New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Scenario\INSTALL -Name UpdateURL -PropertyType String -Value $ChannelCDN -force|Out-Null
		New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Scenario\INSTALL -Name UpdatesEnabled -PropertyType String -Value "True" -force|Out-Null
		New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Scenario\INSTALL -Name MediaType -PropertyType String -Value "CDN" -force|Out-Null
		New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Scenario\INSTALL -Name SourceType -PropertyType String -Value "CDN" -force|Out-Null


		reg delete HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\Configuration /v UpdateUrl /f|Out-Null
		reg delete HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\Configuration /v UpdateToVersion /f|Out-Null
		reg delete HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\Updates /v UpdateToVersion /f|Out-Null
		reg delete HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Office\16.0\Common\OfficeUpdate\ /f|Out-Null
		
		# Pin C2R's hi-pri GPO reg's to ME channel
		New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\office\16.0\common\ -Name officeupdate -force |Out-Null
		New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate -Name updatebranch -PropertyType String -Value $UpdateChannel |Out-Null
		New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate -Name EnableAutomaticUpdates -PropertyType DWORD -Value 1 |Out-Null
		New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate -Name HideEnableDisableUpdates -PropertyType DWORD -Value 1 |Out-Null
		
		# Tell c2r to change channels however its undocumentedly ways work
		start "$Env:CommonProgramFiles\microsoft shared\ClickToRun\OfficeC2RClient.exe" -ArgumentList "/changeSetting Channel=$channel"
		#saps "$Env:CommonProgramFiles\microsoft shared\ClickToRun\OfficeC2RClient.exe" -ArgumentList "/update user displaylevel=false forceappshutdown=true"
		#start-process "$Env:CommonProgramFiles\microsoft shared\ClickToRun\OfficeC2RClient.exe" -ArgumentList "/update user"

		if ( ('true' -eq $?) -and (0 -eq $LASTEXITCODE) ) {
			write-host -ForegroundColor green "		###########################################################################################
			 UpdateChannel set to $Updatechannel, processing update request
		###########################################################################################
			"

		if (($SetUpMeth -notin $validUpMethOpt)){
			Show-UpdateMenu
			$GUIUpMeth = Read-Host "Please make a selection"
			$UMargwrite = "FALSE";
			$UpMeth = $GUIUpMeth;
		}else{
			$UMargwrite = "TRUE";
			$UpMeth = $SetUpMeth;
		}

		$UMopt = "/update user";
		# cd "$Env:CommonProgramFiles\microsoft shared\ClickToRun" ; .\OfficeC2RClient.exe /update user displaylevel=false forceappshutdown=true
		function Run-update {saps "$Env:CommonProgramFiles\microsoft shared\ClickToRun\OfficeC2RClient.exe" $UMopt}

		if ($UpMeth -in $validUpMethOpt) {
			switch ($UpMeth) {
				'1' {

					$UMopt = "/update user displaylevel=false forceappshutdown=true"
					Write-Host ""
					Write-Host -ForegroundColor green "1 - Forcing update and auto close apps for channel: $UpdateChannel (session resume/document recovery on re-open)"
					Write-Host ""
					Run-update; 
				} '2' {
					Write-Host ""
					Write-Host -ForegroundColor green "2 - Politely requested userland update via C2R GUI for channel: $UpdateChannel"
					Write-Host ""
					Run-Update;
				} '0' {
					Write-Host ""
					Write-Host -ForegroundColor green "0 - No Update - exiting. Confirmation: Update channel was modified to: $UpdateChannel"
					Write-Host ""
				}
			}
		}else{
			Write-Host -ForegroundColor green "Invalid update method selected, exiting"
		}

			sleep 2;
			exit 0;
		}else{
			write-host -ForegroundColor red  "		###########################################################################################
		     FAIL - posh operation  win32app exit error :
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
