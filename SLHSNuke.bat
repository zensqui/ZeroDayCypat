@echo off

color 0a

::------------------------------------- Check for permissions
echo Checking if script contains Administrative rights...
net sessions
if %errorlevel%==0 (
echo Administrative Rights certified... Welcome
goto Skip
) else (
echo No admin, prompting for elevation...
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params = %*:"=""
    echo UAC.ShellExecute "cmd.exe", "/c %~s0 %params%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
exit
)
:Skip

    pushd "%CD%"
    CD /D "%~dp0"

echo[
type ASCII.txt
title Nuke Script
echo[

::========================Preliminary Dependencies================================
	echo Get current running directory, check for powershell
set "SourcePath=%~dp0"

echo "%SourcePath%"

	echo %SourcePath%output> "%SourcePath%resources\path.txt"
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine" /v "PowerShellVersion" /z >nul
	If %ERRORLEVEL% == 1 (
		echo POWERSHELL NOT INSTALLED, please install before continuing
		pause>nul
		exit
	)
pause
::==============================Extra Registry Settings===============================
::Add auditing to Lsass.exe
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 00000008 /f
::Enable LSA protection
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 00000001 /f

::Windows automatic updates
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AutoInstallMinorUpdates /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AUOptions /t REG_DWORD /d 4 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 4 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v ElevateNonAdmins /t REG_DWORD /d 0 /f
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoWindowsUpdate /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\Internet Communication Management\Internet Communication" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f

::Enable User Account Control - Unimplemented in Kevin Script *********************
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f

::Internet Explorer security
	::Enable smart screen for IE8 **********************
		reg ADD "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV8 /t REG_DWORD /d 1 /f
	::Enable smart screen for IE9 and up *****************
		reg ADD "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1 /f
	::Disable IE password caching
		reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v DisablePasswordCaching /t REG_DWORD /d 1 /f
	::Warn users if website has a bad certificate
		reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonBadCertRecving /t REG_DWORD /d 1 /f
	::Warn users if website redirects
		reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnOnPostRedirect /t REG_DWORD /d 1 /f
	::Enable Do Not Track
		reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main" /v DoNotTrack /t REG_DWORD /d 1 /f
		reg ADD "HKCU\Software\Microsoft\Internet Explorer\Download" /v RunInvalidSignatures /t REG_DWORD /d 0 /f
		reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings" /v LOCALMACHINE_CD_UNLOCK /t REG_DWORD /d 0 /f
		reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonZoneCrossing /t REG_DWORD /d 1 /f

::Show hidden files
	reg ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v Hidden /t REG_DWORD /d 1 /f
::Show super hidden files
	reg ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v ShowSuperHidden /t REG_DWORD /d 1 /f

::Disable sticky keys
	reg ADD "HKU\.DEFAULT\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 506 /f

::Control Panel -> System -> Advanced Disable dump file creation
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\CrashControl /v CrashDumpEnabled /t REG_DWORD /d 0 /f

::Disable autoruns
	reg ADD HKCU\SYSTEM\CurrentControlSet\Services\CDROM /v AutoRun /t REG_DWORD /d 1 /f

::Disabling Administrative Shares
	REG ADD HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters /v AutoShareWks /t REG_DWORD /d 0 /f
::Disable Ipv6 Networking protocol (BAD)
	REG ADD HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters /v DisabledComponents /t REG_DWORD /d 0xff /f
::Enable Windows Smartscreen (Settings)
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "Block" /f
	REG ADD "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 2 /f
	REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\AppHost" /v EnableWebContentEvaluation /t REG_DWORD /d 1 /f
::Disable RDP remote access to computer (Control panel)
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
REM ==================================Preliminary ============================================================================
	
	::cd /D "C:\Users"
	::echo Deleting All Files With the .mp3 Extention in Users - Implement as advanced file search
	::del /S /Q *.mp3
:: echo Deleting Certain Media Files
:: echo It gives you the folder path and name of the file.
:: echo Do not delete them if you need them for something else, like a forensics question.
:: echo Do not delete anything that looks like it is part of the system.
:: echo You need to disable controlled folder access if you have it for this to work, but then reenable it after.
:: del "C:\Users\*.mp3" /s /p /a:-s
:: del "C:\Users\*.mp4" /s /p /a:-s
:: del "C:\Users\*.mov" /s /p /a:-s
:: del "C:\Users\*.txt" /s /p /a:-s
:: del "C:\Users\*.exe" /s /p /a:-s
	::cd /D "%~dp0"
	
	::Main.bat Powershell script which 'checks files'
	:checkFiles
		set /p fleChk="Search System Files? findings copied to fileOutput under 'output' (y/n)"
if %fleChk%==y (
	echo running system file check
	start C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "%SourcePath%resources\Check_Files.ps1" /wait
	pause
	goto:END1
)
if %fleChk%==n (
	echo Skipping file check
	goto:END1
)
echo Invalid input %fleChk%
goto checkFiles
:END1

::---------------------Windows Firewall-----------------------------
echo Enabling firewall (make sure group policy is allowing modifications to the firewall)

netsh advfirewall set allprofiles state on
echo Firewall enabled
echo Setting basic firewall rules..
netsh advfirewall firewall set rule name="Remote Assistance (DCOM-In)" new enable=no 
netsh advfirewall firewall set rule name="Remote Assistance (PNRP-In)" new enable=no 
netsh advfirewall firewall set rule name="Remote Assistance (RA Server TCP-In)" new enable=no 
netsh advfirewall firewall set rule name="Remote Assistance (SSDP TCP-In)" new enable=no 
netsh advfirewall firewall set rule name="Remote Assistance (SSDP UDP-In)" new enable=no 
netsh advfirewall firewall set rule name="Remote Assistance (TCP-In)" new enable=no 
netsh advfirewall firewall set rule name="Telnet Server" new enable=no 
netsh advfirewall firewall set rule name="netcat" new enable=no
echo Set basic firewall rules

REM ==================================Configures Local Security Policy settings===============================================
::Account Policies
	echo Exporting and updating Password Security Policy settings...
	echo Set account lockout to 5, min length to 8, max age to 30, min age to 10, and history to5
		net accounts /lockoutthreshold:5 /MINPWLEN:8 /MAXPWAGE:30 /MINPWAGE:10 /UNIQUEPW:5 
	echo Updating Account Lockout Policy
		net accounts /lockoutduration:30
		net accounts /lockoutthreshold:5
		net accounts /lockoutwindow:30

	echo Password meets Complexity
		secedit.exe /export /cfg C:\secconfig.cfg
		powershell -ExecutionPolicy Bypass -Command "(gc C:\secconfig.cfg) -replace 'PasswordComplexity = 0', 'PasswordComplexity = 1' | Out-File -encoding ASCII C:\secconfigupdated.cfg"
		echo Importing Updated Password Security Policy Settings, Will be Deleted...
		secedit.exe /configure /db %windir%\securitynew.sdb /cfg C:\secconfigupdated.cfg /areas SECURITYPOLICY
		echo Import successful...
		del c:\secconfig.cfg
		del c:\secconfigupdated.cfg

	echo Password Not Stored Using Reversible Encryption
		secedit.exe /export /cfg C:\secconfig.cfg
		powershell -ExecutionPolicy Bypass -Command "(gc C:\secconfig.cfg) -replace 'ClearTextPassword = 1', 'ClearTextPassword = 0' | Out-File -encoding ASCII C:\secconfigupdated.cfg"
		echo Importing Updated Password Security Policy Settings, Will be Deleted...
		secedit.exe /configure /db %windir%\securitynew.sdb /cfg C:\secconfigupdated.cfg /areas SECURITYPOLICY
		echo Import successful...
		del c:\secconfig.cfg
		del c:\secconfigupdated.cfg

::Local Policies
	::------------------Audit Policy----------------------------
		echo Setting auditing success and failure for all categories
		auditpol /set /category:* /success:enable /failure:enable
			::Advanced Audit Options
				::Auditing access of Global System Objects
					reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v auditbaseobjects /t REG_DWORD /d 1 /f
				::Auditing Backup and Restore
					reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v fullprivilegeauditing /t REG_DWORD /d 1 /f

	::------------------User Rights Assignment------------------
	
		echo Installing ntrights.exe to C:\Windows\System32
		copy %SourcePath%resources\ntrights.exe C:\Windows\System32
		if exist C:\Windows\System32\ntrights.exe (
			echo Installation succeeded, managing user rights..
			set remove=("Backup Operators" "Everyone" "Power Users" "Users" "NETWORK SERVICE" "LOCAL SERVICE" "Remote Desktop User" "ANONOYMOUS LOGON" "Guest" "Performance Log Users")
			for %%a in (%remove%) do (
					ntrights -U %%a -R SeNetworkLogonRight 
					ntrights -U %%a -R SeIncreaseQuotaPrivilege
					ntrights -U %%a -R SeInteractiveLogonRight
					ntrights -U %%a -R SeRemoteInteractiveLogonRight
					ntrights -U %%a -R SeSystemtimePrivilege
					ntrights -U %%a +R SeDenyNetworkLogonRight
					ntrights -U %%a +R SeDenyRemoteInteractiveLogonRight
					ntrights -U %%a -R SeProfileSingleProcessPrivilege
					ntrights -U %%a -R SeBatchLogonRight
					ntrights -U %%a -R SeUndockPrivilege
					ntrights -U %%a -R SeRestorePrivilege
					ntrights -U %%a -R SeShutdownPrivilege
				)
				ntrights -U "Guests" +R SeDenyBatchLogonRight,SeDenyServiceLogonRight,SeDenyInteractiveLogonRight,SeDenyRemoteInteractiveLogonRight;
				ntrights -U "Administrators" -R SeImpersonatePrivilege
				ntrights -U "Administrator" -R SeImpersonatePrivilege
				ntrights -U "SERVICE" -R SeImpersonatePrivilege
				ntrights -U "LOCAL SERVICE" +R SeImpersonatePrivilege
				ntrights -U "NETWORK SERVICE" +R SeImpersonatePrivilege
				ntrights -U "Administrators" +R SeMachineAccountPrivilege
				ntrights -U "Administrator" +R SeMachineAccountPrivilege
				ntrights -U "Administrators" -R SeIncreaseQuotaPrivilege
				ntrights -U "Administrator" -R SeIncreaseQuotaPrivilege
				ntrights -U "Administrators" -R SeDebugPrivilege
				ntrights -U "Administrator" -R SeDebugPrivilege
				ntrights -U "Administrators" +R SeLockMemoryPrivilege
				ntrights -U "Administrator" +R SeLockMemoryPrivilege
				ntrights -U "Administrators" -R SeBatchLogonRight
				ntrights -U "Administrator" -R SeBatchLogonRight
				echo Managed User Rights
		)

		REM --Installing Needed Packages to edit User Rights Assighnment--
		if not exist C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\UserRights mkdir C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\UserRights
		if not exist C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\UserRights\UserRights.psm1 copy /-Y "%~dp0UserRights.psm1" "C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\UserRights"
		
		echo Setting User rights for guest
		Set "MyCmnd=Unblock-File -Path C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\UserRights\UserRights.psm1;"
		Set "MyCmnd=%MyCmnd% Import-Module  UserRights -Force;"
		Set "MyCmnd=%MyCmnd% Grant-UserRight -Account "Guests" -Right SeDenyBatchLogonRight,SeDenyServiceLogonRight,SeDenyInteractiveLogonRight,SeDenyRemoteInteractiveLogonRight;"
		powershell -ExecutionPolicy Unrestricted -Command "%MyCmnd%"
		REM -Uninstalling packages-
		if exist C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\UserRights @RD /S /Q "C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\UserRights"
		echo User rights finished

	:: -----------------Security Options------------------------
		::Allow Machine ID for NTLM
			REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v UseMachineId /t REG_DWORD /d 1 /f
		::Allow LocalSystem NULL session fallback' is set to 'Disabled'
			REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0 /v AllowNullSessionFallback /t REG_DWORD /d 0 /f
		::Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'
			REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa\pku2u /v AllowOnlineID /t REG_DWORD /d 0 /f
		::Configure encryption types allowed for Kerberos' is set to 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types' (*POTENTIAL FAIL)
			REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters /v SupportedEncryptionTypes /t REG_DWORD /d 2147483640 /f
		::Do not store LAN Manager hash value on next password change' is set to 'Enabled'
			REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v NoLMHash /t REG_DWORD /d 1 /f
		::LAN Manager Authentication Level
			REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LmCompatibilityLevel /t REG_DWORD /d 5 /f
		::LDAP client security: Negotiate signing or higher
			REG ADD HKLM\SYSTEM\CurrentControlSet\Services\LDAP /v LDAPClientIntegrity /t REG_DWORD /d 1 /f
		::Require SSP
			REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0 /v NtlmMinClientSec /t REG_DWORD /d 536870912 /f
			REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0 /v NtlmMinServerSec /t REG_DWORD /d 536870912 /f
		::Block all Microsoft Accounts **********************************************
			REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v NoConnectedUser /t REG_DWORD /d 3 /f
			
		::Number of previous logons to cache 0 logons
			REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CachedLogonsCount /t REG_SZ /d 0 /f			
		::Restrict CD-ROM/floppy access to locally logged on user 'Enabled'
			REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateCDRoms /t REG_SZ /d 1 /f
			REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateFloppies /t REG_SZ /d 1 /f
			::reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateCDRoms /t REG_DWORD /d 1 /f
			::reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateFloppies /t REG_DWORD /d 1 /f CONFLICT  ************* DWORD vs REG_SZ
		::Smart card removal behavior 'Lock Workstation'
			REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v ScRemoveOption /t REG_SZ /d 1 /f
		::Unsigned driver/non-driver installation behavior Warn
			REG ADD "HKLM\Software\Microsoft\Driver Signing" /v Policy /t REG_BINARY /d 02 /f
			REG ADD "HKLM\SOFTWARE\Microsoft\Non-Driver Signing" /v Policy /t REG_BINARY /d 02 /f
		::Clear virtual memory pagefile: ENABLED
			REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f
		::RDP network level authentication Enabled
			REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f
		::Network access: Do not allow anonymous enumeration of SAM accounts
			reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymous /t REG_DWORD /d 1 /f
			reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymoussam /t REG_DWORD /d 1 /f
		::Disable storage of domain passwords
			reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v disabledomaincreds /t REG_DWORD /d 1 /f
		::Take away Anonymous user Everyone permissions 'Network access: Let everyone permissions apply to anonymous users'
			reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v everyoneincludesanonymous /t REG_DWORD /d 0 /f
		::User Account Control: Detect application installations and prompt for elevation
			reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableInstallerDetection /t REG_DWORD /d 1 /f
		::MSS: Enable Automatic Administrative Logon 'Disabled'
			reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /d 0 /f 
		::Devices: Allow Undock Without Having to Log On 'Disabled'
			reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v undockwithoutlogon /t REG_DWORD /d 0 /f
		::Domain Member: Maximum Machine Account Password Age '15'
			reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v MaximumPasswordAge /t REG_DWORD /d 15 /f
		::Domain member: Disable machine account password changes 'Enabled' DONT YOU WANT TO DISABLE THIS(STIG)? ********************************
			reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v DisablePasswordChange /t REG_DWORD /d 1 /f
		::Domain member: Require strong (Windows 2000 or Later) session key 'Enabled'
			reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireStrongKey /t REG_DWORD /d 1 /f
		::Domain member: Digitally encrypt or sign secure channel data (always) 'Enabled'
			reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireSignOrSeal /t REG_DWORD /d 1 /f
		::Domain member: Digitally sign secure channel data (when possible) 'Enabled'
			reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SignSecureChannel /t REG_DWORD /d 1 /f
		::Domain member: Digitally encrypt secure channel data (when possible) 'Enabled'
			reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SealSecureChannel /t REG_DWORD /d 1 /f
		::Microsoft network server: Amount of idle time required before suspending a session '15 minutes'
			reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v autodisconnect /t REG_DWORD /d 15 /f
		::Microsoft network server: Digitally sign communications (if Client agrees) 'Enabled'
			reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v enablesecuritysignature /t REG_DWORD /d 1 /f
		::Microsoft network server: Digitally sign communications (always) 'Enabled'
			reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v requiresecuritysignature /t REG_DWORD /d 1 /f
		::Network access: Named pipes that can be accessed anonymously, ensure empty
			reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionPipes /t REG_MULTI_SZ /d "" /f
		::Network access: Shares that can be accessed anonymously, ensure empty
			reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionShares /t REG_MULTI_SZ /d "" /f
		::Network access: Remotely accessible registry paths, ensure empty
			reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths /v Machine /t REG_MULTI_SZ /d "" /f
		::Network access: Remotely accessible registry paths and sub-paths, ensure empty
			reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths /v Machine /t REG_MULTI_SZ /d "" /f

::Creating dependencies
if not exist %SystemRoot%\script-logs\ (
  mkdir %SystemRoot%\script-logs\
    )
echo (new-object -c "microsoft.update.servicemanager").addservice2("7971f918-a847-4430-9279-4a52d1efe18d",7,"") > %TEMP%\tempscript.ps1
		
		::Secpol14 Updates for other Microsoft products Enabled - NOT secpol solution!
			sc config wuauserv start= auto
			reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 3 /f
			powershell -ExecutionPolicy Unrestricted %TEMP%\tempscript.ps1 >> %SystemRoot%\script-logs\Computer-Turn-On-Application-Updates.log.txt

		::Interactive Logon: Do not require CTRL+ALT+DEL 'Disabled'
			reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v DisableCAD /t REG_DWORD /d 0 /f
		::Set “Network access: Restrict anonymous access to Named Pipes and Shares” to Enabled
			REG ADD HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters /v RestrictNullSessAccess /t REG_DWORD /d 1 /f
		::User Account Control: Enforce secure desktop
			REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableUIADesktopToggle /t REG_DWORD /d 0 /f
			REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
		::Recovery console: Allow automatic administrative logon  Disabled
			REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole" /v SecurityLevel /t REG_DWORD /d 0 /f
		::Microsoft network client: Send unencrypted password to third-party SMB servers 'Disabled'
			reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
		::Devices: Prevent users from installing printer drivers  Enabled
			REG ADD "HKLM\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f
		
		:: Do Not Display Last Username At Logon Screen Enabled
			secedit.exe /export /cfg C:\secconfig.cfg
			powershell -Command "(gc C:\secconfig.cfg) -replace 'DontDisplayLastUserName=4,0', 'DontDisplayLastUserName=4,1' | Out-File -encoding ASCII C:\secconfigupdated.cfg"
			secedit.exe /configure /db %windir%\securitynew.sdb /cfg C:\secconfigupdated.cfg /areas SECURITYPOLICY
			del c:\secconfig.cfg
			del c:\secconfigupdated.cfg
				::Alt ::Do not display last user on logon reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v dontdisplaylastusername /t REG_DWORD /d 1 /f
		::Limit Local Use of Blank Passwords to Console Only
			secedit.exe /export /cfg C:\secconfig.cfg
			powershell -Command "(gc C:\secconfig.cfg) -replace 'LimitBlankPasswordUse=4,0', 'LimitBlankPasswordUse=4,1' | Out-File -encoding ASCII C:\secconfigupdated.cfg"
			secedit.exe /configure /db %windir%\securitynew.sdb /cfg C:\secconfigupdated.cfg /areas SECURITYPOLICY
			del c:\secconfig.cfg
			del c:\secconfigupdated.cfg
				::Alt ::Limit use of blank passwords reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f



REM ==================================Configures Local User Manager Settings====================================================
	echo Disabling Guest/Admin
	net user Guest /active no
	net user Administrator /active no

	echo Renaming Guest/Admin Accounts to 'RenamdGeust,RenamdAdm'
	echo Default Administrator Account Renamed
	wmic useraccount where name='Administrator' rename 'RenamdAdm'
	echo Default Guest Account Renamed
	wmic useraccount where name='Guest' rename 'RenamdGeust'
	::start C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "%SourcePath%resources\RenameDefAccounts.ps1"

REM Retrieving set user password *********Seems kinda funky
set "File2Read=Password.json"
setlocal EnableExtensions EnableDelayedExpansion
    set /a count = 0
set /p Password=<Password.json
    echo "Password" is assigned to ==^> "!Password!"

echo Making passwords expire, setting user passwords
echo Please change the main account password after script
::Setting all user passwords to Password.json
	FOR /F %%F IN ('wmic useraccount get name') DO (Echo "%%F" | FIND /I "Name" 1>NUL) || (Echo "%%F" | FIND /I "DefaultAccount" 1>NUL) || (
		NET USER %%F "!Password!"
		C:\Windows\System32\wbem\wmic UserAccount where Name="%%F" set PasswordExpires=True
		)
		for /f "tokens=*" %%a in ('type %SourcePath%resources\users.txt') do (
	C:\Windows\System32\wbem\wmic UserAccount where Name="%%a" set PasswordExpires=True
		)
echo Made passwords expire, and set passwords

REM ==================================Configuring Services & Windows Features====================================================
::------------------Services.msc----------------------------
	::Disable 'Bluetooth Audio Gateway Service (BTAGService)','Bluetooth Support Service (bthserv)' 
		net stop BTAGService
		net stop bthserv
		sc config BTAGService start= disabled
		sc config bthserv start= disabled
	::Ensure 'Downloaded Maps Manager (MapsBroker)' is set to 'Disabled'
		net stop MapsBroker
		sc config MapsBroker start= disabled
	::Ensure 'Geolocation Service (lfsvc)' is set to 'Disabled'
		net stop lfsvc
		sc config lfsvc start= disabled
	::Ensure 'IIS Admin Service (IISADMIN)' is set to 'Disabled' or 'Not Installed'
		net stop IISADMIN
		sc config IISADMIN start= disabled
	::Ensure 'Infrared monitor service (irmon)' is set to 'Disabled'
		net stop irmon
		sc config irmon start= disabled
	::Ensure 'Internet Connection Sharing (ICS) (SharedAccess)' is set to 'Disabled'
		net stop SharedAccess
		sc config "SharedAccess" start= disabled
	::Ensure 'Link-Layer Topology Discovery Mapper (lltdsvc)' is set to 'Disabled'
		net stop lltdsvc
		sc config lltdsvc start= disabled
	::Ensure 'LxssManager (LxssManager)' is set to 'Disabled' or 'Not Installed'
		net stop LxssManager
		sc config LxssManager start= disabled
	::Ensure 'Microsoft FTP Service (FTPSVC)' is set to 'Disabled' or 'Not Installed'
		net stop FTPSVC
		sc config FTPSVC start= disabled
	::Ensure 'Microsoft iSCSI Initiator Service (MSiSCSI)' is set to 'Disabled'
		net stop MSiSCSI
		sc config MSiSCSI start= disabled
	::Ensure 'Microsoft Store Install Service (InstallService)' is set to 'Disabled'
		net stop InstallService
		sc config InstallService start= disabled
	::Ensure 'OpenSSH SSH Server (sshd)' is set to 'Disabled' or 'Not Installed'
		net stop sshd
		sc config sshd start= disabled
	::Ensure 'Peer Name Resolution Protocol (PNRPsvc)' is set to 'Disabled'
		net stop PNRPsvc
		sc config PNRPsvc start= disabled
	::Ensure 'Peer Networking Grouping (p2psvc)' is set to 'Disabled'
		net stop p2psvc
		sc config p2psvc start= disabled
	::Ensure 'Peer Networking Identity Manager (p2pimsvc)' is set to 'Disabled'
		net stop p2pimsvc
		sc config p2pimsvc start= disabled
	::Ensure 'PNRP Machine Name Publication Service (PNRPAutoReg)' is set to 'Disabled'
		net stop PNRPAutoReg
		sc config PNRPAutoReg start= disabled
	::Ensure 'Problem Reports and Solutions Control Panel Support (wercplsupport)' is set to 'Disabled'
		net stop wercplsupport
		sc config wercplsupport start= disabled
	::Ensure 'Remote Access Auto Connection Manager (RasAuto)' is set to 'Disabled'
		net stop RasAuto
		sc config RasAuto start= disabled
	::Ensure 'Remote Desktop Configuration (SessionEnv)' is set to 'Disabled'
		net stop SessionEnv
		sc config SessionEnv start= disabled
	::Ensure 'Remote Desktop Services (TermService)' is set to 'Disabled'
		net stop TermService
		sc config TermService start= disabled
	::Ensure 'Remote Desktop Services UserMode Port Redirector (UmRdpService)' is set to 'Disabled'
		net stop UmRdpService
		sc config UmRdpService start= disabled
	::Ensure 'Remote Procedure Call (RPC) Locator (RpcLocator)' is set to 'Disabled'
		net stop RpcLocator
		sc config RpcLocator start= disabled
	::Ensure 'Remote Registry (RemoteRegistry)' is set to 'Disabled'
		net stop RemoteRegistry
		sc config "RemoteRegistry" start= disabled
	::Ensure 'Routing and Remote Access (RemoteAccess)' is set to 'Disabled'
		net stop RemoteAccess
		sc config RemoteAccess start= disabled
	::Ensure 'Server (LanmanServer)' is set to 'Disabled'
		net stop LanmanServer
		sc config LanmanServer start= disabled
	::Ensure 'Simple TCP/IP Services (simptcp)' is set to 'Disabled' or 'Not Installed'
		net stop simptcp
		sc config simptcp start= disabled
	::Ensure 'SNMP Service (SNMP)' is set to 'Disabled' or 'Not Installed
		net stop SNMP
		sc config SNMP start= disabled
	::Ensure 'SSDP Discovery (SSDPSRV)' is set to 'Disabled'
		net stop SSDPSRV
		sc config "SSDPSRV" start= disabled
	::Ensure 'UPnP Device Host (upnphost)' is set to 'Disabled'
		net stop upnphost
		sc config "upnphost" start= disabled
	::Ensure 'Web Management Service (WMSvc)' is set to 'Disabled' or 'Not Installed'
		net stop WMSvc
		sc config WMSvc start= disabled
	::Ensure 'Windows Media Player Network Sharing Service (WMPNetworkSvc)' is set to 'Disabled' or 'Not Installed'
		net stop WMPNetworkSvc
		sc config WMPNetworkSvc start= disabled
	::Ensure 'Windows Mobile Hotspot Service (icssvc)' is set to 'Disabled'
		net stop icssvc
		sc config icssvc start= disabled
	::Ensure 'Windows Push Notifications System Service (WpnService)' is set to 'Disabled'
		net stop WpnService
		sc config WpnService start= disabled
	::Ensure 'Windows PushToInstall Service (PushToInstall)' is set to 'Disabled'
		net stop PushToInstall
		sc config PushToInstall start= disabled
	::Ensure 'Windows Remote Management (WS-Management) (WinRM)' is set to 'Disabled'
		net stop WinRM
		sc config WinRM start= disabled
	::Ensure 'Xbox Accessory Management Service (XboxGipSvc)' is set to 'Disabled'
		net stop XboxGipSvc
		sc config XboxGipSvc start= disabled
	::Ensure 'Xbox Live Auth Manager (XblAuthManager)' is set to 'Disabled'
		net stop XblAuthManager
		sc config XblAuthManager start= disabled
	::Ensure 'Xbox Live Game Save (XblGameSave)' is set to 'Disabled'
		net stop XblGameSave
		sc config XblGameSave start= disabled
	::Ensure 'Xbox Live Networking Service (XboxNetApiSvc)' is set to 'Disabled'
		net stop XboxNetApiSvc
		sc config XboxNetApiSvc start= disabled
	::Ensure Windows Update Service is enabled as automatic on startup
		sc config wuauserv start= auto
		net start wuauserv
	::Disable Printer Spooler
		net stop Spooler
		sc config Spooler start= disabled
	::Disable Net.Tcp port sharing service
		net stop NetTcpPortSharing
		sc config NetTcpPortSharing start= disabled
	::Ensure ‘WebClient' is set to 'Disabled’
		net stop WebClient
		sc config WebClient start= disabled
	::Ensure 'Fax' is set to 'Disabled'
		net stop Fax
		sc config Fax start= disabled
	::Ensure 'Telephony' is set to 'Disabled'
		net stop Telephony
		sc config Telephony start= disabled


::Some extras, too lazy to comply
set servicesD=RemoteAccess Telephony TapiSrv Tlntsvr tlntsvr p2pimsvc simptcp fax msftpsvc iprip ftpsvc RemoteRegistry RasMan RasAuto seclogon MSFTPSVC W3SVC SMTPSVC Dfs TrkWks MSDTC DNS ERSVC NtFrs MSFtpsvc helpsvc HTTPFilter IISADMIN IsmServ WmdmPmSN Spooler RDSessMgr RPCLocator RsoPProv	ShellHWDetection ScardSvr Sacsvr TermService Uploadmgr VDS VSS WINS WinHttpAutoProxySvc SZCSVC CscService hidserv IPBusEnum PolicyAgent SCPolicySvc SharedAccess SSDPSRV Themes upnphost nfssvc nfsclnt MSSQLServerADHelper
set servicesM=dmserver SrvcSurg
set servicesG=Dhcp Dnscache NtLmSsp Sense eventlog WinDefend

echo Disabling bad services...
for %%a in (%servicesD%) do (
	echo Service: %%a
	sc stop "%%a"
	sc config "%%a" start= disabled
)
echo Disabled bad services
echo Setting services to manual...
for %%b in (%servicesM%) do (
	echo Service: %%b
	sc config "%%b" start= demand
)
echo Set services to manual
echo Seting services to auto...
for %%c in (%servicesG%) do (
	echo Service: %%c
	sc config "%%c" start= auto
	sc start "%%c"
)
echo Started auto services
::----------------Windows Features-----------------------
	REM Disabling Windows Features
	echo Installing Dism.exe
	copy %SourcePath%resources\Dism.exe C:\Windows\System32
	xcopy %SourcePath%resources\Dism C:\Windows\System32
	echo "DISABLING WINDOWS FEATURES"

	echo Disabling SMBv1
	powershell -ExecutionPolicy Bypass -Command "Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol"
	echo Disabling SNMP
	DISM /online /disable-feature /featurename:SNMP
	echo Disabling Remote Assistance
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
		netsh advfirewall firewall set rule group="Remote Assistance" new enable=no

::----------------Remote Desktop Protocol-----------------
:rdp
set /p rdpChk="Enable remote desktop (y/n)"
if %rdpChk%==y (
	echo Enabling remote desktop...
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowTSConnections /t REG_DWORD /d 1 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 1 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
	netsh advfirewall firewall set rule group="remote desktop" new enable=yes
	echo Please select "Allow connections only from computers running Remote Desktop with Network Level Authentication (more secure)"
	start SystemPropertiesRemote.exe /wait
	pause
	sc config TermService start= manual
	echo Enabled remote desktop
	goto:END
)
if %rdpChk%==n (
	echo Disabling remote desktop...
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowTSConnections /t REG_DWORD /d 0 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
	netsh advfirewall firewall set rule group="remote desktop" new enable=no
	echo Disabled remote desktop
	goto:END
)
echo Invalid input %rdpChk%
goto rdp
:END

::===========================Extra================================================
::Flushing DNS cache
echo Flushing DNS
ipconfig /flushdns >nul
::clearing Host file
echo Clearing Host File (contents of: C:\Windows\System32\drivers\etc\hosts )
attrib -r -s C:\WINDOWS\system32\drivers\etc\hosts
echo > C:\Windows\System32\drivers\etc\hosts
attrib +r +s C:\WINDOWS\system32\drivers\etc\hosts

echo Cleaning Host File alt method
copy %WinDir%\System32\drivers\etc\hosts %WinDir%\System32\drivers\etc\hosts.old
break > %WinDir%\System32\drivers\etc\hosts
::Setting power settings
echo Setting power settings...
powercfg -SETDCVALUEINDEX SCHEME_BALANCED SUB_NONE CONSOLELOCK 1
powercfg -SETDCVALUEINDEX SCHEME_MIN SUB_NONE CONSOLELOCK 1
powercfg -SETDCVALUEINDEX SCHEME_MAX SUB_NONE CONSOLELOCK 1
echo Set power settings
REM Remove all saved saved password credentials
cmdkey.exe /list > "%TEMP%\List.txt"
findstr.exe Target "%TEMP%\List.txt" > "%TEMP%\tokensonly.txt"
FOR /F "tokens=1,2 delims= " %%G IN (%TEMP%\tokensonly.txt) DO cmdkey.exe /delete:%%H
del "%TEMP%\*.*" /s /f /q

echo Enabling DEP Protection
bcdedit.exe /set {current} nx AlwaysOn

echo Obtaining DNS Server Address Automatically Enabled
netsh interface ipv4 set dnsservers name="Ethernet" source=dhcp

::===========================Running Tools/Info Txt files============================
echo Deleting C drive Share
net share C:\ /delete
echo Echoing network shares to %SourcePath%output\shares.txt, make sure to check for out of place shares
net share > %SourcePath%output\shares.txt

echo Manage users according to readme...
start %SourcePath%output\users.txt

echo Process Explorer, startup tab, verify signatures
start %SourcePath%resources\WSCC\Sysinternals\procexp.exe
echo Autoruns
start %SourcePath%resources\WSCC\Sysinternals\Autoruns.exe
::=============================Final lengthy Disk integrity/other processes============
REM START SYS INTEG SCAN!
echo "STARTING SYSTEM INTERGRITY SCAN"
echo "If it fails make sure you can access Sfc.exe"
::Protected file integrity scan (checks for issues only)
::sfc /verifyonly

::EXTRAPOTENTIAL:
	::First Run.bat option 4 file search, quite extensive. Option 2 process list could be useful for a quick check
