@echo off

color 0b


type ASCII.txt

title Vector Shield

cd /D "%~dp0"

REG ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa /v UseMachineId /t REG_DWORD /d 1 /f
REG ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0 /v AllowNullSessionFallback /t REG_DWORD /d 0 /f
REG ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\pku2u /v AllowOnlineID /t REG_DWORD /d 0 /f
REG ADD HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters /v SupportedEncryptionTypes /t REG_DWORD /d 2147483640 /f
REG ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa /v NoLMHash /t REG_DWORD /d 1 /f

REG ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa /v LmCompatibilityLevel /t REG_DWORD /d 5 /f
REG ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LDAP /v LDAPClientIntegrity /t REG_DWORD /d 1 /f
REG ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0 /v NtlmMinClientSec /t REG_DWORD /d 536870912 /f
REG ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0 /v NtlmMinServerSec /t REG_DWORD /d 536870912 /f
DISM /online /Disable-feature /featurename:TelnetClient
DISM /online /Disable-Feature /FeatureName:TFTP
sc stop Fax
sc config Fax start= disabled
REG ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters /v DisabledComponents /t REG_DWORD /d 0xff /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "Block" /f
REG ADD "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 2 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\AppHost" /v EnableWebContentEvaluation /t REG_DWORD /d 1 /f
netsh advfirewall set allprofiles state on
Auditpol /set /category:"Account Logon" /success:enable /failure:enable
Auditpol /set /category:"Account Management" /success:enable /failure:enable
Auditpol /set /category:"Detailed Tracking" /success:enable /failure:enable
Auditpol /set /category:"DS Access" /success:enable /failure:enable
Auditpol /set /category:"Logon/Logoff" /Success:enable /failure:enable
Auditpol /set /category:"Object Access" /success:enable /failure:enable
Auditpol /set /category:"Policy Change" /success:enable /failure:enable
Auditpol /set /category:"Privilege Use" /success:enable /failure:enable
Auditpol /set /category:"System" /success:enable /failure:enable
REG ADD HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v NoConnectedUser /t REG_DWORD /d 3 /f
REG ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa /v RestrictAnonymous /t REG_DWORD /d 1 /f
REG ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters /v requiresecuritysignature /t REG_DWORD /d 1 /f
secedit.exe /export /cfg C:\secconfig.cfg
powershell -Command "(gc C:\secconfig.cfg) -replace 'DontDisplayLastUserName=4,0', 'DontDisplayLastUserName=4,1' | Out-File -encoding ASCII C:\secconfigupdated.cfg"
secedit.exe /configure /db %windir%\securitynew.sdb /cfg C:\secconfigupdated.cfg /areas SECURITYPOLICY
del c:\secconfig.cfg
del c:\secconfigupdated.cfg

REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CachedLogonsCount /t REG_SZ /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateCDRoms /t REG_SZ /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateFloppies /t REG_SZ /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v ScRemoveOption /t REG_SZ /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Microsoft\Driver Signing" /v Policy /t REG_BINARY /d 02 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Non-Driver Signing" /v Policy /t REG_BINARY /d 02 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f
secedit.exe /export /cfg C:\secconfig.cfg
powershell -Command "(gc C:\secconfig.cfg) -replace 'LimitBlankPasswordUse=4,0', 'LimitBlankPasswordUse=4,1' | Out-File -encoding ASCII C:\secconfigupdated.cfg"
secedit.exe /configure /db %windir%\securitynew.sdb /cfg C:\secconfigupdated.cfg /areas SECURITYPOLICY
del c:\secconfig.cfg
del c:\secconfigupdated.cfg

  mkdir %SystemRoot%\script-logs\
sc config wuauserv start= auto
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 3 /f
powershell -ExecutionPolicy Unrestricted %TEMP%\tempscript.ps1 >> %SystemRoot%\script-logs\Computer-Turn-On-Application-Updates.log.txt

REG ADD HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableCAD /t REG_DWORD /d 0 /f
REG ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters /v RestrictNullSessAccess /t REG_DWORD /d 1 /f
REG ADD HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableUIADesktopToggle /t REG_DWORD /d 0 /f
REG ADD HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole" /v SecurityLevel /t REG_DWORD /d 0 /f


REG ADD HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
 REG ADD "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f

net user Guest /active no
net user Administrator /active no

Set "MyCmnd=Unblock-File -Path C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\UserRights\UserRights.psm1;"
Set "MyCmnd=%MyCmnd% Import-Module  UserRights -Force;"
Set "MyCmnd=%MyCmnd% $Accounts=Get-AccountsWithUserRight -Right SeTrustedCredManAccessPrivilege;"
Set "MyCmnd=%MyCmnd% $Counter = $Counter = $($Accounts | measure).Count;"
Set "MyCmnd=%MyCmnd% For ($i=0; $i -lt $Counter; $i++)  {Revoke-UserRight -Account "$Accounts[$i].SID" -Right SeTrustedCredManAccessPrivilege};"
powershell -ExecutionPolicy Unrestricted -Command "%MyCmnd%"


Set "MyCmnd=Unblock-File -Path C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\UserRights\UserRights.psm1;"
Set "MyCmnd=%MyCmnd% Import-Module  UserRights -Force;"
Set "MyCmnd=%MyCmnd% $Accounts=Get-AccountsWithUserRight -Right SeNetworkLogonRight;"
Set "MyCmnd=%MyCmnd% $Counter = $Counter = $($Accounts | measure).Count;"
Set "MyCmnd=%MyCmnd% For ($i=0; $i -lt $Counter; $i++)  {Revoke-UserRight -Account "$Accounts[$i].SID" -Right SeNetworkLogonRight};"
Set "MyCmnd=%MyCmnd% Grant-UserRight -Account "Administrators" -Right SeNetworkLogonRight;"
Set "MyCmnd=%MyCmnd% Grant-UserRight -Account "S-1-5-32-555" -Right SeNetworkLogonRight;"
powershell -ExecutionPolicy Unrestricted -Command "%MyCmnd%"

Set "MyCmnd=Unblock-File -Path C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\UserRights\UserRights.psm1;"
Set "MyCmnd=%MyCmnd% Import-Module  UserRights -Force;"
Set "MyCmnd=%MyCmnd% $Accounts=Get-AccountsWithUserRight -Right SeTcbPrivilege;"
Set "MyCmnd=%MyCmnd% $Counter = $Counter = $($Accounts | measure).Count;"
Set "MyCmnd=%MyCmnd% For ($i=0; $i -lt $Counter; $i++)  {Revoke-UserRight -Account "$Accounts[$i].SID" -Right SeTcbPrivilege};"
powershell -ExecutionPolicy Unrestricted -Command "%MyCmnd%"

Set "MyCmnd=Unblock-File -Path C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\UserRights\UserRights.psm1;"
Set "MyCmnd=%MyCmnd% Import-Module  UserRights -Force;"
Set "MyCmnd=%MyCmnd% $Accounts=Get-AccountsWithUserRight -Right SeIncreaseQuotaPrivilege;"
Set "MyCmnd=%MyCmnd% $Counter = $Counter = $($Accounts | measure).Count;"
Set "MyCmnd=%MyCmnd% For ($i=0; $i -lt $Counter; $i++)  {Revoke-UserRight -Account "$Accounts[$i].SID" -Right SeIncreaseQuotaPrivilege};"
Set "MyCmnd=%MyCmnd% Grant-UserRight -Account "Administrators" -Right SeIncreaseQuotaPrivilege;"
Set "MyCmnd=%MyCmnd% Grant-UserRight -Account "S-1-5-19" -Right SeIncreaseQuotaPrivilege;"
Set "MyCmnd=%MyCmnd% Grant-UserRight -Account "S-1-5-20" -Right SeIncreaseQuotaPrivilege;"
powershell -ExecutionPolicy Unrestricted -Command "%MyCmnd%"

Set "MyCmnd=Unblock-File -Path C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\UserRights\UserRights.psm1;"
Set "MyCmnd=%MyCmnd% Import-Module  UserRights -Force;"
Set "MyCmnd=%MyCmnd% $Accounts=Get-AccountsWithUserRight -Right SeBackupPrivilege;"
Set "MyCmnd=%MyCmnd% $Counter = $Counter = $($Accounts | measure).Count;"
Set "MyCmnd=%MyCmnd% For ($i=0; $i -lt $Counter; $i++)  {Revoke-UserRight -Account "$Accounts[$i].SID" -Right SeBackupPrivilege};"
Set "MyCmnd=%MyCmnd% Grant-UserRight -Account "Administrators" -Right SeBackupPrivilege;"
powershell -ExecutionPolicy Unrestricted -Command "%MyCmnd%"

Set "MyCmnd=Unblock-File -Path C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\UserRights\UserRights.psm1;"
Set "MyCmnd=%MyCmnd% Import-Module  UserRights -Force;"
Set "MyCmnd=%MyCmnd% $Accounts=Get-AccountsWithUserRight -Right SeTimeZonePrivilege;"
Set "MyCmnd=%MyCmnd% $Counter = $Counter = $($Accounts | measure).Count;"
Set "MyCmnd=%MyCmnd% For ($i=0; $i -lt $Counter; $i++)  {Revoke-UserRight -Account "$Accounts[$i].SID" -Right SeTimeZonePrivilege};"
Set "MyCmnd=%MyCmnd% Grant-UserRight -Account "Administrators" -Right SeTimeZonePrivilege;"
Set "MyCmnd=%MyCmnd% Grant-UserRight -Account "S-1-5-19" -Right SeTimeZonePrivilege;"
Set "MyCmnd=%MyCmnd% Grant-UserRight -Account "Users" -Right SeTimeZonePrivilege;"
powershell -ExecutionPolicy Unrestricted -Command "%MyCmnd%"

Set "MyCmnd=Unblock-File -Path C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\UserRights\UserRights.psm1;"
Set "MyCmnd=%MyCmnd% Import-Module  UserRights -Force;"
Set "MyCmnd=%MyCmnd% $Accounts=Get-AccountsWithUserRight -Right SeCreatePagefilePrivilege;"
Set "MyCmnd=%MyCmnd% $Counter = $Counter = $($Accounts | measure).Count;"
Set "MyCmnd=%MyCmnd% For ($i=0; $i -lt $Counter; $i++)  {Revoke-UserRight -Account "$Accounts[$i].SID" -Right SeCreatePagefilePrivilege};"
Set "MyCmnd=%MyCmnd% Grant-UserRight -Account "Administrators" -Right SeCreatePagefilePrivilege;"

Set "MyCmnd=%MyCmnd% $Accounts=Get-AccountsWithUserRight -Right SeCreateTokenPrivilege;"
Set "MyCmnd=%MyCmnd% $Counter = $Counter = $($Accounts | measure).Count;"
Set "MyCmnd=%MyCmnd% For ($i=0; $i -lt $Counter; $i++)  {Revoke-UserRight -Account "$Accounts[$i].SID" -Right SeCreateTokenPrivilege};"

Set "MyCmnd=%MyCmnd% $Accounts=Get-AccountsWithUserRight -Right SeCreateGlobalPrivilege;"
Set "MyCmnd=%MyCmnd% $Counter = $Counter = $($Accounts | measure).Count;"
Set "MyCmnd=%MyCmnd% For ($i=0; $i -lt $Counter; $i++)  {Revoke-UserRight -Account "$Accounts[$i].SID" -Right SeCreateGlobalPrivilege};"
Set "MyCmnd=%MyCmnd% Grant-UserRight -Account "Administrators" -Right SeCreateGlobalPrivilege;"
Set "MyCmnd=%MyCmnd% Grant-UserRight -Account "S-1-5-19" -Right SeCreateGlobalPrivilege;"
Set "MyCmnd=%MyCmnd% Grant-UserRight -Account "S-1-5-20" -Right SeCreateGlobalPrivilege;"
Set "MyCmnd=%MyCmnd% Grant-UserRight -Account "S-1-5-6" -Right SeCreateGlobalPrivilege;"

Set "MyCmnd=%MyCmnd% $Accounts=Get-AccountsWithUserRight -Right SeCreatePermanentPrivilege;"
Set "MyCmnd=%MyCmnd% $Counter = $Counter = $($Accounts | measure).Count;"
Set "MyCmnd=%MyCmnd% For ($i=0; $i -lt $Counter; $i++)  {Revoke-UserRight -Account "$Accounts[$i].SID" -Right SeCreatePermanentPrivilege};"
powershell -ExecutionPolicy Unrestricted -Command "%MyCmnd%"

Set "MyCmnd=Unblock-File -Path C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\UserRights\UserRights.psm1;"
Set "MyCmnd=%MyCmnd% Import-Module  UserRights -Force;"
Set "MyCmnd=%MyCmnd% $Accounts=Get-AccountsWithUserRight -Right SeCreateSymbolicLinkPrivilege;"
Set "MyCmnd=%MyCmnd% $Counter = $Counter = $($Accounts | measure).Count;"
Set "MyCmnd=%MyCmnd% For ($i=0; $i -lt $Counter; $i++)  {Revoke-UserRight -Account "$Accounts[$i].SID" -Right SeCreateSymbolicLinkPrivilege};"
Set "MyCmnd=%MyCmnd% Grant-UserRight -Account "Administrators" -Right SeCreateSymbolicLinkPrivilege;"
powershell -ExecutionPolicy Unrestricted -Command "%MyCmnd%"

Set "MyCmnd=Unblock-File -Path C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\UserRights\UserRights.psm1;"
Set "MyCmnd=%MyCmnd% Import-Module  UserRights -Force;"
Set "MyCmnd=%MyCmnd% $Accounts=Get-AccountsWithUserRight -Right SeDebugPrivilege;"
Set "MyCmnd=%MyCmnd% $Counter = $Counter = $($Accounts | measure).Count;"
Set "MyCmnd=%MyCmnd% For ($i=0; $i -lt $Counter; $i++)  {Revoke-UserRight -Account "$Accounts[$i].SID" -Right SeDebugPrivilege};"
Set "MyCmnd=%MyCmnd% Grant-UserRight -Account "Administrators" -Right SeDebugPrivilege;"
powershell -ExecutionPolicy Unrestricted -Command "%MyCmnd%"

Set "MyCmnd=Unblock-File -Path C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\UserRights\UserRights.psm1;"
Set "MyCmnd=%MyCmnd% Import-Module  UserRights -Force;"
Set "MyCmnd=%MyCmnd% Grant-UserRight -Account "Guests" -Right SeDenyBatchLogonRight,SeDenyServiceLogonRight,SeDenyInteractiveLogonRight,SeDenyRemoteInteractiveLogonRight;"
powershell -ExecutionPolicy Unrestricted -Command "%MyCmnd%"

Set "MyCmnd=Unblock-File -Path C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\UserRights\UserRights.psm1;"
Set "MyCmnd=%MyCmnd% Import-Module  UserRights -Force;"
Set "MyCmnd=%MyCmnd% $Accounts=Get-AccountsWithUserRight -Right SeBatchLogonRight;"
Set "MyCmnd=%MyCmnd% $Counter = $Counter = $($Accounts | measure).Count;"
Set "MyCmnd=%MyCmnd% For ($i=0; $i -lt $Counter; $i++)  {Revoke-UserRight -Account "$Accounts[$i].SID" -Right SeBatchLogonRight};"
Set "MyCmnd=%MyCmnd% Grant-UserRight -Account "Administrators" -Right SeBatchLogonRight;"
powershell -ExecutionPolicy Unrestricted -Command "%MyCmnd%"

Set "MyCmnd=Unblock-File -Path C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\UserRights\UserRights.psm1;"
Set "MyCmnd=%MyCmnd% Import-Module  UserRights -Force;"
Set "MyCmnd=%MyCmnd% $Accounts=Get-AccountsWithUserRight -Right SeServiceLogonRight;"
Set "MyCmnd=%MyCmnd% $Counter = $Counter = $($Accounts | measure).Count;"
Set "MyCmnd=%MyCmnd% For ($i=0; $i -lt $Counter; $i++)  {Revoke-UserRight -Account "$Accounts[$i].SID" -Right SeServiceLogonRight};"
powershell -ExecutionPolicy Unrestricted -Command "%MyCmnd%"

Set "MyCmnd=Unblock-File -Path C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\UserRights\UserRights.psm1;"
Set "MyCmnd=%MyCmnd% Import-Module  UserRights -Force;"
Set "MyCmnd=%MyCmnd% $Accounts=Get-AccountsWithUserRight -Right SeEnableDelegationPrivilege;"
Set "MyCmnd=%MyCmnd% $Counter = $Counter = $($Accounts | measure).Count;"
Set "MyCmnd=%MyCmnd% For ($i=0; $i -lt $Counter; $i++)  {Revoke-UserRight -Account "$Accounts[$i].SID" -Right SeEnableDelegationPrivilege};"
powershell -ExecutionPolicy Unrestricted -Command "%MyCmnd%"

Set "MyCmnd=Unblock-File -Path C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\UserRights\UserRights.psm1;"
Set "MyCmnd=%MyCmnd% Import-Module  UserRights -Force;"
Set "MyCmnd=%MyCmnd% $Accounts=Get-AccountsWithUserRight -Right SeRemoteShutdownPrivilege;"
Set "MyCmnd=%MyCmnd% $Counter = $Counter = $($Accounts | measure).Count;"
Set "MyCmnd=%MyCmnd% For ($i=0; $i -lt $Counter; $i++)  {Revoke-UserRight -Account "$Accounts[$i].SID" -Right SeRemoteShutdownPrivilege};"
Set "MyCmnd=%MyCmnd% Grant-UserRight -Account "Administrators" -Right SeRemoteShutdownPrivilege;"
powershell -ExecutionPolicy Unrestricted -Command "%MyCmnd%"

Set "MyCmnd=Unblock-File -Path C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\UserRights\UserRights.psm1;"
Set "MyCmnd=%MyCmnd% Import-Module  UserRights -Force;"
Set "MyCmnd=%MyCmnd% $Accounts=Get-AccountsWithUserRight -Right SeAuditPrivilege;"
Set "MyCmnd=%MyCmnd% $Counter = $Counter = $($Accounts | measure).Count;"
Set "MyCmnd=%MyCmnd% For ($i=0; $i -lt $Counter; $i++)  {Revoke-UserRight -Account "$Accounts[$i].SID" -Right SeAuditPrivilege};"
Set "MyCmnd=%MyCmnd% Grant-UserRight -Account "S-1-5-19" -Right SeAuditPrivilege;"
Set "MyCmnd=%MyCmnd% Grant-UserRight -Account "S-1-5-20" -Right SeAuditPrivilege;"
powershell -ExecutionPolicy Unrestricted -Command "%MyCmnd%"

Set "MyCmnd=Unblock-File -Path C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\UserRights\UserRights.psm1;"
Set "MyCmnd=%MyCmnd% Import-Module  UserRights -Force;"
Set "MyCmnd=%MyCmnd% $Accounts=Get-AccountsWithUserRight -Right SeImpersonatePrivilege;"
Set "MyCmnd=%MyCmnd% $Counter = $Counter = $($Accounts | measure).Count;"
Set "MyCmnd=%MyCmnd% For ($i=0; $i -lt $Counter; $i++)  {Revoke-UserRight -Account "$Accounts[$i].SID" -Right SeImpersonatePrivilege};"
Set "MyCmnd=%MyCmnd% Grant-UserRight -Account "Administrators" -Right SeImpersonatePrivilege;"
Set "MyCmnd=%MyCmnd% Grant-UserRight -Account "S-1-5-20" -Right SeImpersonatePrivilege;"
Set "MyCmnd=%MyCmnd% Grant-UserRight -Account "S-1-5-19" -Right SeImpersonatePrivilege;"
Set "MyCmnd=%MyCmnd% Grant-UserRight -Account "S-1-5-6" -Right SeImpersonatePrivilege;"
powershell -ExecutionPolicy Unrestricted -Command "%MyCmnd%"

Set "MyCmnd=Unblock-File -Path C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\UserRights\UserRights.psm1;"
Set "MyCmnd=%MyCmnd% Import-Module  UserRights -Force;"
Set "MyCmnd=%MyCmnd% $Accounts=Get-AccountsWithUserRight -Right SeIncreaseBasePriorityPrivilege;"
Set "MyCmnd=%MyCmnd% $Counter = $Counter = $($Accounts | measure).Count;"
Set "MyCmnd=%MyCmnd% For ($i=0; $i -lt $Counter; $i++)  {Revoke-UserRight -Account "$Accounts[$i].SID" -Right SeIncreaseBasePriorityPrivilege};"
Set "MyCmnd=%MyCmnd% Grant-UserRight -Account "Administrators" -Right SeIncreaseBasePriorityPrivilege;"
Set "MyCmnd=%MyCmnd% Grant-UserRight -Account "S-1-5-90-0" -Right SeIncreaseBasePriorityPrivilege;"
powershell -ExecutionPolicy Unrestricted -Command "%MyCmnd%"

Set "MyCmnd=Unblock-File -Path C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\UserRights\UserRights.psm1;"
Set "MyCmnd=%MyCmnd% Import-Module  UserRights -Force;"
Set "MyCmnd=%MyCmnd% $Accounts=Get-AccountsWithUserRight -Right SeLoadDriverPrivilege;"
Set "MyCmnd=%MyCmnd% $Counter = $Counter = $($Accounts | measure).Count;"
Set "MyCmnd=%MyCmnd% For ($i=0; $i -lt $Counter; $i++)  {Revoke-UserRight -Account "$Accounts[$i].SID" -Right SeLoadDriverPrivilege};"
Set "MyCmnd=%MyCmnd% Grant-UserRight -Account "Administrators" -Right SeLoadDriverPrivilege;"
powershell -ExecutionPolicy Unrestricted -Command "%MyCmnd%"

Set "MyCmnd=Unblock-File -Path C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\UserRights\UserRights.psm1;"
Set "MyCmnd=%MyCmnd% Import-Module  UserRights -Force;"
Set "MyCmnd=%MyCmnd% $Accounts=Get-AccountsWithUserRight -Right SeLockMemoryPrivilege;"
Set "MyCmnd=%MyCmnd% $Counter = $Counter = $($Accounts | measure).Count;"
Set "MyCmnd=%MyCmnd% For ($i=0; $i -lt $Counter; $i++)  {Revoke-UserRight -Account "$Accounts[$i].SID" -Right SeLockMemoryPrivilege};"
powershell -ExecutionPolicy Unrestricted -Command "%MyCmnd%"

Set "MyCmnd=Unblock-File -Path C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\UserRights\UserRights.psm1;"
Set "MyCmnd=%MyCmnd% Import-Module  UserRights -Force;"
Set "MyCmnd=%MyCmnd% $Accounts=Get-AccountsWithUserRight -Right SeRelabelPrivilege;"
Set "MyCmnd=%MyCmnd% $Counter = $Counter = $($Accounts | measure).Count;"
Set "MyCmnd=%MyCmnd% For ($i=0; $i -lt $Counter; $i++)  {Revoke-UserRight -Account "$Accounts[$i].SID" -Right SeRelabelPrivilege};"
powershell -ExecutionPolicy Unrestricted -Command "%MyCmnd%"

Set "MyCmnd=Unblock-File -Path C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\UserRights\UserRights.psm1;"
Set "MyCmnd=%MyCmnd% Import-Module  UserRights -Force;"
Set "MyCmnd=%MyCmnd% $Accounts=Get-AccountsWithUserRight -Right SeSystemEnvironmentPrivilege;"
Set "MyCmnd=%MyCmnd% $Counter = $Counter = $($Accounts | measure).Count;"
Set "MyCmnd=%MyCmnd% For ($i=0; $i -lt $Counter; $i++)  {Revoke-UserRight -Account "$Accounts[$i].SID" -Right SeSystemEnvironmentPrivilege};"
Set "MyCmnd=%MyCmnd% Grant-UserRight -Account "Administrators" -Right SeSystemEnvironmentPrivilege;"
powershell -ExecutionPolicy Unrestricted -Command "%MyCmnd%"

Set "MyCmnd=Unblock-File -Path C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\UserRights\UserRights.psm1;"
Set "MyCmnd=%MyCmnd% Import-Module  UserRights -Force;"
Set "MyCmnd=%MyCmnd% $Accounts=Get-AccountsWithUserRight -Right SeManageVolumePrivilege;"
Set "MyCmnd=%MyCmnd% $Counter = $Counter = $($Accounts | measure).Count;"
Set "MyCmnd=%MyCmnd% For ($i=0; $i -lt $Counter; $i++)  {Revoke-UserRight -Account "$Accounts[$i].SID" -Right SeManageVolumePrivilege};"
Set "MyCmnd=%MyCmnd% Grant-UserRight -Account "Administrators" -Right SeManageVolumePrivilege;"
powershell -ExecutionPolicy Unrestricted -Command "%MyCmnd%"

Set "MyCmnd=Unblock-File -Path C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\UserRights\UserRights.psm1;"
Set "MyCmnd=%MyCmnd% Import-Module  UserRights -Force;"
Set "MyCmnd=%MyCmnd% $Accounts=Get-AccountsWithUserRight -Right SeProfileSingleProcessPrivilege;"
Set "MyCmnd=%MyCmnd% $Counter = $Counter = $($Accounts | measure).Count;"
Set "MyCmnd=%MyCmnd% For ($i=0; $i -lt $Counter; $i++)  {Revoke-UserRight -Account "$Accounts[$i].SID" -Right SeProfileSingleProcessPrivilege};"
Set "MyCmnd=%MyCmnd% Grant-UserRight -Account "Administrators" -Right SeProfileSingleProcessPrivilege;"

Set "MyCmnd=%MyCmnd% $Accounts=Get-AccountsWithUserRight -Right SeSystemProfilePrivilege;"
Set "MyCmnd=%MyCmnd% $Counter = $Counter = $($Accounts | measure).Count;"
Set "MyCmnd=%MyCmnd% For ($i=0; $i -lt $Counter; $i++)  {Revoke-UserRight -Account "$Accounts[$i].SID" -Right SeSystemProfilePrivilege};"
Set "MyCmnd=%MyCmnd% Grant-UserRight -Account "Administrators" -Right SeSystemProfilePrivilege;"
Set "MyCmnd=%MyCmnd% Grant-UserRight -Account "S-1-5-80" -Right SeSystemProfilePrivilege;"
powershell -ExecutionPolicy Unrestricted -Command "%MyCmnd%"

Set "MyCmnd=Unblock-File -Path C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\UserRights\UserRights.psm1;"
Set "MyCmnd=%MyCmnd% Import-Module  UserRights -Force;"
Set "MyCmnd=%MyCmnd% $Accounts=Get-AccountsWithUserRight -Right SeAssignPrimaryTokenPrivilege;"
Set "MyCmnd=%MyCmnd% $Counter = $Counter = $($Accounts | measure).Count;"
Set "MyCmnd=%MyCmnd% For ($i=0; $i -lt $Counter; $i++)  {Revoke-UserRight -Account "$Accounts[$i].SID" -Right SeAssignPrimaryTokenPrivilege};"
Set "MyCmnd=%MyCmnd% Grant-UserRight -Account "S-1-5-19" -Right SeAssignPrimaryTokenPrivilege;"
Set "MyCmnd=%MyCmnd% Grant-UserRight -Account "S-1-5-20" -Right SeAssignPrimaryTokenPrivilege;"
powershell -ExecutionPolicy Unrestricted -Command "%MyCmnd%"

Set "MyCmnd=Unblock-File -Path C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\UserRights\UserRights.psm1;"
Set "MyCmnd=%MyCmnd% Import-Module  UserRights -Force;"
Set "MyCmnd=%MyCmnd% $Accounts=Get-AccountsWithUserRight -Right SeRestorePrivilege;"
Set "MyCmnd=%MyCmnd% $Counter = $Counter = $($Accounts | measure).Count;"
Set "MyCmnd=%MyCmnd% For ($i=0; $i -lt $Counter; $i++)  {Revoke-UserRight -Account "$Accounts[$i].SID" -Right SeRestorePrivilege};"
Set "MyCmnd=%MyCmnd% Grant-UserRight -Account "Administrators" -Right SeRestorePrivilege;"
powershell -ExecutionPolicy Unrestricted -Command "%MyCmnd%"

Set "MyCmnd=Unblock-File -Path C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\UserRights\UserRights.psm1;"
Set "MyCmnd=%MyCmnd% Import-Module  UserRights -Force;"
Set "MyCmnd=%MyCmnd% $Accounts=Get-AccountsWithUserRight -Right SeShutdownPrivilege;"
Set "MyCmnd=%MyCmnd% $Counter = $Counter = $($Accounts | measure).Count;"
Set "MyCmnd=%MyCmnd% For ($i=0; $i -lt $Counter; $i++)  {Revoke-UserRight -Account "$Accounts[$i].SID" -Right SeShutdownPrivilege};"
Set "MyCmnd=%MyCmnd% Grant-UserRight -Account "Administrators" -Right SeShutdownPrivilege;"
Set "MyCmnd=%MyCmnd% Grant-UserRight -Account "Users" -Right SeShutdownPrivilege;"
powershell -ExecutionPolicy Unrestricted -Command "%MyCmnd%"

Set "MyCmnd=Unblock-File -Path C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\UserRights\UserRights.psm1;"
Set "MyCmnd=%MyCmnd% Import-Module  UserRights -Force;"
Set "MyCmnd=%MyCmnd% $Accounts=Get-AccountsWithUserRight -Right SeTakeOwnershipPrivilege;"
Set "MyCmnd=%MyCmnd% $Counter = $Counter = $($Accounts | measure).Count;"
Set "MyCmnd=%MyCmnd% For ($i=0; $i -lt $Counter; $i++)  {Revoke-UserRight -Account "$Accounts[$i].SID" -Right SeTakeOwnershipPrivilege};"
Set "MyCmnd=%MyCmnd% Grant-UserRight -Account "Administrators" -Right SeTakeOwnershipPrivilege;"
powershell -ExecutionPolicy Unrestricted -Command "%MyCmnd%"

sc stop BTAGService
sc stop bthserv
sc config BTAGService start= disabled
sc config bthserv start= disabled
sc stop MapsBroker
sc config MapsBroker start= disabled
sc stop lfsvc
sc config lfsvc start= disabled
sc stop IISADMIN
sc config IISADMIN start= disabled
sc stop irmon
sc config irmon start= disabled
sc stop SharedAccess
sc config "SharedAccess" start= disabled
sc stop lltdsvc
sc config lltdsvc start= disabled
sc stop LxssManager
sc config LxssManager start= disabled
sc stop FTPSVC
sc config FTPSVC start= disabled
sc stop MSiSCSI
sc config MSiSCSI start= disabled
sc stop InstallService
sc config InstallService start= disabled
sc stop sshd
sc config sshd start= disabled
sc stop PNRPsvc
sc config PNRPsvc start= disabled
sc stop p2psvc
sc config p2psvc start= disabled
sc stop p2pimsvc
sc config p2pimsvc start= disabled
sc stop PNRPAutoReg
sc config PNRPAutoReg start= disabled
sc stop wercplsupport
sc config wercplsupport start= disabled
sc stop RasAuto
sc config RasAuto start= disabled
sc stop SessionEnv
sc config SessionEnv start= disabled
sc stop TermService
sc config TermService start= disabled
sc stop UmRdpService
sc config UmRdpService start= disabled
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
sc stop RpcLocator
sc config RpcLocator start= disabled
sc stop RemoteRegistry
sc config "RemoteRegistry" start= disabled
sc stop RemoteAccess
sc config RemoteAccess start= disabled
sc stop LanmanServer
sc config LanmanServer start= disabled
sc stop simptcp
sc config simptcp start= disabled
sc stop SNMP
sc config SNMP start= disabled
sc stop SSDPSRV
sc config "SSDPSRV" start= disabled
sc stop upnphost
sc config "upnphost" start= disabled
sc stop WMSvc
sc config WMSvc start= disabled
sc stop WerSvc
sc config WerSvc start= disabled
sc stop Wecsvc
sc config Wecsvc start= disabled
sc stop WMPNetworkSvc
sc config WMPNetworkSvc start= disabled
sc stop icssvc
sc config icssvc start= disabled
sc stop WpnService
sc config WpnService start= disabled
sc stop PushToInstall
sc config PushToInstall start= disabled
sc stop WinRM
sc config WinRM start= disabled
sc stop XboxGipSvc
sc config XboxGipSvc start= disabled
sc stop XblAuthManager
sc config XblAuthManager start= disabled
sc stop XblGameSave
sc config XblGameSave start= disabled
sc stop XboxNetApiSvc
sc config XboxNetApiSvc start= disabled
sc config wuauserv start= auto
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 3 /f
sc stop Spooler
sc config Spooler start= disabled
sc stop NetTcpPortSharing
sc config NetTcpPortSharing start= disabled
sc stop WebClient
sc config WebClient start= disabled

FOR /F %%F IN ('wmic useraccount get name') DO (Echo "%%F" | FIND /I "Name" 1>NUL) || (Echo "%%F" | FIND /I "DefaultAccount" 1>NUL) || (NET USER %%F "!Password!")
cd /D "C:\Users"
del /S /Q *.mp3
cd /D "%~dp0"
wmic useraccount where name='Administrator' rename 'VS1'
wmic useraccount where name='Guest' rename 'VS2'
REG ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters /v AutoShareWks /t REG_DWORD /d 0 /f
exit