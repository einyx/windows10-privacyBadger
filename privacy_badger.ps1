$tweaks = @(
	### Require administrator privileges ###
    ##"Restart"
    "DisableAppSuggestions",
    "DisableSmartScreen",
    "DisableWebContentEvaluation",
    "DisablePishingFilter",
    "DisableDefender",
    "DisableSpyNetReporting",
    "DisableSecHealth",
    "DisableSense",
    "DisableStore",
    "RemoveMsApps",
    "DisableUpdates",
    "DisableServicePush",
    "DisableXboxService",
    "DisablerMapBroker",
    "DisalbeLfSvc",
    "DisableSystemRestore",
    "DisableEdge",
    "DisableCortana",
    "DisableErrorReporting",
    "DisableSettingSync",
    "DisableCloudContent",
    "DisableStylus",
    "DisableDiagnosticTracking",
    "DisablePushService",
    "DisableTelemetry",
    "DisableSync",
    "DisableMessagingService",
    "DisableReportsAndSolutionsControl",
    "DisablePCA",
    "DisableSigninAssistant",
    "DisableWindowsInsider",
    "DisableRetailDemo",
    "DisableDiag"
    
    )



Function Restart {
	Write-Output "Restarting..."
	Restart-Computer
}
Function Pin-App {    param(
        [string]$appname,
        [switch]$unpin
    )
    try{
        if ($unpin.IsPresent){
            ((New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() | ?{$_.Name -eq $appname}).Verbs() | ?{$_.Name.replace('&','') -match 'Von "Start" lösen|Unpin from Start'} | %{$_.DoIt()}
            return "App '$appname' unpinned from Start"
        }else{
            ((New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() | ?{$_.Name -eq $appname}).Verbs() | ?{$_.Name.replace('&','') -match 'An "Start" anheften|Pin to Start'} | %{$_.DoIt()}
            return "App '$appname' pinned to Start"
        }
    }catch{
        Write-Error "Error Pinning/Unpinning App! (App-Name correct?)"
    }
}


Function DisableUpdates {
	Write-Output "Disabling driver offering through Windows Update..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Type DWord -Value 1
}
Function DisableAppSuggestions {
    Write-Output "Disabling Application suggestions..."
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
        If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
}

# Disable Smart screen
Function DisableSmartScreen {
    New-Item -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled"
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off"  -PropertyType "String"
}


# Disable web content evaluation
Function DisableWebContentEvaluation {
    New-Item -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnabledV9"
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Value "0" -PropertyType "DWord"
}

# Disable phishing filter
Function DisablePishingFilter {
    New-Item -Force -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" -Name "EnabledV9"
    New-ItemProperty -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Value "0" -PropertyType "DWord"
}

# Disable Defender
Function DisableDefender {
    New-Item -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware"
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value "1" -PropertyType "DWord"
}

# Disable SpyNet Reporting
Function DisableSpyNetReporting {
    New-Item -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpyNetReporting"
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpyNetReporting" -Value "0" -PropertyType "DWord"
    New-Item -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent"
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Value "2" -PropertyType "DWord"
    New-Item -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "DontReportInfectionInformation"
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "DontReportInfectionInformation" -Value "1" -PropertyType "DWord"
    New-Item -Path -Force "HKLM:\SOFTWARE\Policies\Microsoft\MR" -Name "DontReportInfectionInformation" 
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontReportInfectionInformation" -Value "1" -PropertyType "DWord"
    New-Item -Path -Force "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUA" 
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUA" -Value "" -PropertyType "DWord"
}

Function DisableSecHealth {
New-Item -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SecHealthUI.exe"
New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SecHealthUI.exeT" -Name "Debugger" -Value "%windir%\System32\taskkill.exe" -PropertyType "String"
}

Function DisableSense {
    Remove-Item -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sense"
    Remove-Item -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    Remove-ItemProperty -Force -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" -Value "SecurityHealth"
}

Function DisableStore {
    New-Item -Force -Path "HKLM:\Software\Policies\Microsoft\WindowsStore" 
    New-Item -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost"
    New-Item -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\PushToInstall"
    New-Item -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    Get-AppxPackage -AllUsers *store* | Remove-AppxPackage
}

Function DisableXboxService {
    sc delete XblAuthManager
    sc delete XblGameSave
    sc delete XboxNetApiSvc
    sc delete XboxGipSvc
    schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTask" /disable
    schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTaskLogon" /disable
    schtasks /Change /TN "\Microsoft\Windows\HelloFace\FODCleanupTask" /Disable
    Remove-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value "0" -PropertyType "DWord"
    Remove-Item -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\xbgm"
}
# Remove Store

Function RemoveMsApps {
# Remove Multimedia
    Get-AppxPackage -AllUsers *zune* | Remove-AppxPackage
    Get-WindowsPackage -Online | Where PackageName -like *MediaPlayer* | Remove-WindowsPackage -Online -NoRestart
    Get-AppxPackage -AllUsers *xbox* | Remove-AppxPackage
    Get-AppxPackage -AllUsers *sticky* | Remove-AppxPackage
    Get-AppxPackage -AllUsers *maps* | Remove-AppxPackage
    Get-AppxPackage -AllUsers *alarms* | Remove-AppxPackage
    Get-AppxPackage -AllUsers *people* | Remove-AppxPackage
    Get-AppxPackage -AllUsers *comm* | Remove-AppxPackage
    Get-AppxPackage -AllUsers *mess* | Remove-AppxPackage
    Get-AppxPackage -AllUsers *onenote* | Remove-AppxPackage
    Get-AppxPackage -AllUsers *photo* | Remove-AppxPackage
    Get-AppxPackage -AllUsers *camera* | Remove-AppxPackage
    Get-AppxPackage -AllUsers *bing* | Remove-AppxPackage
    Get-AppxPackage -AllUsers *mixed* | Remove-AppxPackage
    Get-AppxPackage -AllUsers *feedback* | Remove-AppxPackage
    Get-AppxPackage -AllUsers *plans* | Remove-AppxPackage
    Get-AppxPackage -AllUsers *skype* | Remove-AppxPackage
    Get-AppxPackage -AllUsers *3d* | Remove-AppxPackage
    Get-AppxPackage -AllUsers *connect* | Remove-AppxPackage
    Get-AppxPackage -AllUsers *started* | Remove-AppxPackage
    Get-AppxPackage -AllUsers *sechealth* | Remove-AppxPackage
    Get-AppxPackage -AllUsers *office* | Remove-AppxPackage
    Get-AppxPackage -AllUsers *paint* | Remove-AppxPackage
    Get-AppxPackage -AllUsers *onedrive* | Remove-AppxPackage
    Get-AppxPackage -AllUsers *calc* | Remove-AppxPackage
    Get-AppxPackage -AllUsers *sketch* | Remove-AppxPackage
    Get-AppxPackage -AllUsers *solitaire* | Remove-AppxPackage
    Get-AppxPackage -AllUsers *soundrec* | Remove-AppxPackage
    Get-AppxPackage -AllUsers *phone* | Remove-AppxPackage
    Get-AppxPackage -AllUsers *GetHelp* | Remove-AppxPackage
    Get-WindowsPackage -Online | Where PackageName -like *QuickAssist* | Remove-WindowsPackage -Online -NoRestart
    Get-WindowsPackage -Online | Where PackageName -like *Hello-Face* | Remove-WindowsPackage -Online -NoRestart
}

# Provides infrastructure support for the Microsoft Store
Function DisableServicePush{
    sc delete PushToInstall
}

Function DisableMapBroker {
    sc delete MapsBroker
    schtasks /Change /TN "\Microsoft\Windows\Maps\MapsUpdateTask" /disable
    schtasks /Change /TN "\Microsoft\Windows\Maps\MapsToastTask" /disable
}


Function DisalbeLfSvc {
    sc delete lfsvc
}

Function DisableSystemRestore {
    Disable-ComputerRestore -Drive "C:\"
    vssadmin delete shadows /all /Quiet
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableConfig" /t "REG_DWORD" /d "1" /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableSR " /t "REG_DWORD" /d "1" /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableConfig" /t "REG_DWORD" /d "1" /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableSR " /t "REG_DWORD" /d "1" /f
    schtasks /Change /TN "\Microsoft\Windows\SystemRestore\SR" /disable
}




Function DisableEdge {
# EDGE
    taskkill /F /IM browser_broker.exe
    taskkill /F /IM RuntimeBroker.exe
    taskkill /F /IM MicrosoftEdge.exe
    taskkill /F /IM MicrosoftEdgeCP.exe
    taskkill /F /IM MicrosoftEdgeSH.exe
    mv C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe_BAK
    Remove-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MicrosoftEdge.exe" -Name "Debugger" -Value "%windir%\System32\taskkill.exe" -PropertyType "String"
    Get-WindowsPackage -Online | Where PackageName -like *InternetExplorer* | Remove-WindowsPackage -Online -NoRestart
}

Function DisableCortana {
# Cortana
    New-Item -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortanba" -Value "0" -PropertyType "DWord"
    New-Item -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" 
    New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" -Name "{2765E0F4-2918-4A46-B9C9-43CDD8FCBA2B}" -Value "BlockCortana|Action=Block|Active=TRUE|Dir=Out|App=C:\windows\systemapps\microsoft.windows.cortana_cw5n1h2txyewy\searchui.exe|Name=Search  and Cortana  application|AppPkgId=S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742|" -ProepertyType "String"
    New-Item -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"
    New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value "0" -PropertyType "DWord"
}

Function DisableErrorReporting {
    New-Item -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value "1" -PropertyType "DWord"
    New-Item -Force -Path "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform"
    New-ItemProperty -Force -Path "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name "NoGenTicket" -Value "1" -PropertyType "DWord"
}

Function DisableSettingSync {
    New-Item -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\SettingSync"
    New-ItemProperty -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\SettingSync" -Name "DisableSettingSync" -Value "2" -PropertyType "DWord"
    New-ItemProperty -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\SettingSync" -Name "DisableSettingSyncUserOverride" -Value "1" -PropertyType "DWord" 
}

Function DisableCloudContent {
    New-Item -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent"
    reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 1 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
}

Function DisableStylus {
    # The three main Windows Ink Workspace apps are provided by Windows and designed to make
    # using your pen easier and faster.
    New-Item -Force -Path "HKLM\Software\Policies\Microsoft\WindowsInkWorkspace"
    New-ItemProperty -Force -Path "HKLM\Software\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowSuggestedAppsInWindowsInkWorkspace" -Value "0" -PropertyType "DWord"
}


# Disable Diagnostick tracking
Function DisableDiagnosticTracking {
    Get-Service DiagTrack | Set-Service -StartupType Disabled
}

# Disable Windows manager push service
Function DisablePushService {
Get-Service dmwappushservice | Set-Service -StartupType Disabled
}

Function DisableTelemetry {
    New-Item -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection"
    reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f
}


# Disable windows error reporting
Function DisableErrorReporting {
    Get-Service WerSvc | Set-Service -StartupType Disabled
}

Function DisableSync {
    # This service synchronizes mail, contacts, calendar and various other user data. 
    # Mail and other applications dependent on this functionality will not work properly 
    # when this service is not running.
    sc delete OneSyncSvc
}

Function DisableMessaginService {
# If MessagingService fails to load or initialize, Windows 10 start up proceeds.
# No warning is displayed, but the error is recorded into the Event Log.
    sc delete MessagingService
}

Function DisableReportsAndSolutionsControl {
    # The Problem Reports and Solutions Control Panel Support service is running as 
    # localSystem in a shared process of svchost.exe. 
    # Other services might run in the same process. If Problem Reports and Solutions 
    # Control Panel Support fails to start, the error is logged. Windows 10 startup proceeds, 
    # but a message box is displayed informing you that the wercplsupport service has failed to start.
    sc delete wercplsupport
}

Function DisablePca {
    sc delete PcaSvc
}

Function DisableSigninAssistant {
    # The Microsoft Account Sign-in Assistant service is running as LocalSystem in a 
    # shared process of svchost.exe. Other services might run in the same process. 
    # If Microsoft Account Sign-in Assistant fails to start, the error is logged. 
    # Windows 10 startup proceeds, but a message box is displayed informing you that 
    # the wlidsvc service has failed to start.
    sc config wlidsvc start=demand
}

Function DisableWindowsInsider {
    # The Windows Insider Service is running as LocalSystem in a shared process of 
    # svchost.exe. Other services might run in the same process. If Windows Insider Service
    # fails to start, the error is logged. Windows 10 startup proceeds, but a message box
    # is displayed informing you that the wisvc service has failed to start.
    sc delete wisvc
}

Function DisableRetailDemo {
    sc delete RetailDemo

}


Function DisableDiag {
    sc delete diagsvc
}

Function DisableShp {
    sc delete shpamsvc 
}

Function DisableTermService {
    sc delete TermService
}

Function DisableRdp {
    sc delete UmRdpService
}

Function DisableSessionEnv {
    sc delete SessionEnv
}

Function DisableTroubleshooting {
    sc delete TroubleshootingSvc
}

#for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "wscsvc" ^| find /i "wscsvc"') do (reg delete %I /f)
#for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "OneSyncSvc" ^| find /i "OneSyncSvc"') do (reg delete %I /f)
#for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "MessagingService" ^| find /i "MessagingService"') do (reg delete %I /f)
#for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "PimIndexMaintenanceSvc" ^| find /i "PimIndexMaintenanceSvc"') do (reg delete %I /f)
#for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "UserDataSvc" ^| find /i "UserDataSvc"') do (reg delete %I /f)
#for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "UnistoreSvc" ^| find /i "UnistoreSvc"') do (reg delete %I /f)
#for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "BcastDVRUserService" ^| find /i "BcastDVRUserService"') do (reg delete %I /f)
#for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "Sgrmbroker" ^| find /i "Sgrmbroker"') do (reg delete %I /f)


sc delete diagnosticshub.standardcollector.service
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f
reg add "HKLM\SYSTEM\ControlSet001\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v Start /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v AITEnable /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableInventory /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisablePCA /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableUAR /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f

schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\AitAgent" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /disable
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /disable
schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /disable
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /disable
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /disable
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /disable
schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" /disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyRefresh" /disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyUpload" /disable
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /disable
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Automatic App Update" /disable
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /disable
schtasks /Change /TN "Microsoft\Windows\Clip\License Validation" /disable
schtasks /Change /TN "\Microsoft\Windows\ApplicationData\DsSvcCleanup" /disable
schtasks /Change /TN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable
schtasks /Change /TN "\Microsoft\Windows\PushToInstall\LoginCheck" /disable
schtasks /Change /TN "\Microsoft\Windows\PushToInstall\Registration" /disable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitor" /disable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitorToastTask" /disable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefreshTask" /disable
schtasks /Change /TN "\Microsoft\Windows\Subscription\EnableLicenseAcquisition" /disable
schtasks /Change /TN "\Microsoft\Windows\Subscription\LicenseAcquisition" /disable
schtasks /Change /TN "\Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner" /disable
schtasks /Change /TN "\Microsoft\Windows\Diagnosis\Scheduled" /disable
schtasks /Change /TN "\Microsoft\Windows\NetTrace\GatherNetworkInfo" /disable
del /F /Q "C:\Windows\System32\Tasks\Microsoft\Windows\SettingSync\*" 

Pin-App "Mail" -unpin
Pin-App "Store" -unpin
Pin-App "Calendar" -unpin
Pin-App "Microsoft Edge" -unpin
Pin-App "Photos" -unpin
Pin-App "Cortana" -unpin
Pin-App "Weather" -unpin
Pin-App "Phone Companion" -unpin
Pin-App "Music" -unpin
Pin-App "xbox" -unpin
Pin-App "movies & tv" -unpin
Pin-App "microsoft solitaire collection" -unpin
Pin-App "money" -unpin
Pin-App "get office" -unpin
Pin-App "onenote" -unpin
Pin-App "news" -unpin
Pin-App "Mail" -unpin
Pin-App "Store" -unpin
Pin-App "Calendar" -unpin
Pin-App "Microsoft Edge" -unpin
Pin-App "Photos" -unpin
Pin-App "Cortana" -unpin
Pin-App "Weather" -unpin
Pin-App "Phone Companion" -unpin
Pin-App "Music" -unpin
Pin-App "xbox" -unpin
Pin-App "movies & tv" -unpin
Pin-App "microsoft solitaire collection" -unpin
Pin-App "money" -unpin
Pin-App "get office" -unpin
Pin-App "onenote" -unpin
Pin-App "news" -unpin 
Pin-App "Paint 3D" -unpin

$tweaks