"
#################################################
###               EZSCRIPT SON                ###
#################################################
"
"What do you want to do today?"
$ConfirmPreference = 'None'

#adjust this variable to user running this script
$user = 'ADJUSTMEBEFORERUNNING'

$option = Read-Host '
1. Soft Cuddly User info :)
2. Upgraded NETSTAT
3. OS file search
 '

if ($option -eq 1) {
    New-Item -Path C:\Users\$user\Desktop\scripterino -ItemType directory
    'no files are safe [.][.]'
    New-Item -Path C:\Users\$user\Desktop\scripterino\userfiles -ItemType directory
    New-Item -Path C:\Users\$user\Desktop\scripterino\programfiles -ItemType directory
    New-Item -Path C:\Users\$user\Desktop\scripterino\programfilesx86 -ItemType directory
    New-Item -Path C:\Users\$user\Desktop\scripterino\documents -ItemType directory
	New-Item -Path C:\Users\$user\Desktop\scripterino\OS_search_engine -ItemType directory
    Write-Warning "grabbing user files"
    Get-ChildItem -Path "C:\Users\*" -Include *.jpg,*.png,*.aac,*.ac3,*.avi,*.aiff,*.bat,*.bmp,*.exe,*.flac,*.gif,*.jpeg,*.mov,*.m3u,*.m4p,*.mp2,*.mp3,*.mp4,*.mpeg4,*.midi,*.msi,*.ogg,*.png,*.txt,*.sh,*.wav,*.wma,*.vqf,*.pcap,*.zip,*.pdf,*.json -Recurse | Copy-Item -Destination C:\Users\$user\Desktop\scripterino\userfiles
    Write-Warning "grabbing program files"
    Get-ChildItem -Path "C:\Program Files\*" -Include *.jpg,*.png,*.aac,*.ac3,*.avi,*.aiff,*.bat,*.bmp,*.exe,*.flac,*.gif,*.jpeg,*.mov,*.m3u,*.m4p,*.mp2,*.mp3,*.mp4,*.mpeg4,*.midi,*.msi,*.ogg,*.png,*.txt,*.sh,*.wav,*.wma,*.vqf,*.pcap,*.zip,*.pdf,*.json -Recurse | Copy-Item -Destination C:\Users\$user\Desktop\scripterino\programfiles
    Get-ChildItem -Path "C:\Program Files (x86)\*" -Include *.jpg,*.png,*.aac,*.ac3,*.avi,*.aiff,*.bat,*.bmp,*.exe,*.flac,*.gif,*.jpeg,*.mov,*.m3u,*.m4p,*.mp2,*.mp3,*.mp4,*.mpeg4,*.midi,*.msi,*.ogg,*.png,*.txt,*.sh,*.wav,*.wma,*.vqf,*.pcap,*.zip,*.pdf,*.json -Recurse | Copy-Item -Destination C:\Users\$user\Desktop\scripterino\programfilesx86
    Write-Warning "grabbing Documents"
    Get-ChildItem -Path "C:\Users\$user\Documents\*" -Include *.jpg,*.png,*.aac,*.ac3,*.avi,*.aiff,*.bat,*.bmp,*.exe,*.flac,*.gif,*.jpeg,*.mov,*.m3u,*.m4p,*.mp2,*.mp3,*.mp4,*.mpeg4,*.midi,*.msi,*.ogg,*.png,*.txt,*.sh,*.wav,*.wma,*.vqf,*.pcap,*.zip,*.pdf,*.json -Recurse | Copy-Item -Destination C:\Users\$user\Desktop\scripterino\documentsandsettings
    Write-Warning "catching them special media files"
    Get-ChildItem -Path C:\Users -Include .jpg,.png,.jpeg,.avi,.mp4,.mp3,*.wav -Exclude .dll,.doc,*.docx,  -File -Recurse -ErrorAction SilentlyContinue | Out-File -filepath C:\Users\$user\Desktop\scripterino\Mediafiles.txt
	'Proceed to search baby ;) keep in mind these are only copies of the originals'

    #setup
    Write-Warning "You chose... peace, no nuke"
    [console]::Beep(800,500)
    Start-Sleep -s 1
    '3'
    [console]::Beep(800,500)
    Start-Sleep -s 1
    '2'
    [console]::Beep(800,500)
    '1'
    Start-Sleep -s 1
    Write-Warning "managing users"
    Write-Warning "performing recon"
    net user > scripterino\users.txt
    net localgroup > scripterino\groups.txt
 

    #grabbing network shares check if irregular
    Write-Warning "grabbing smb shares bb"
    net share > scripterino\shares.txt
    	
    #flush DNS
    Write-Warning "flushing dns cache, y not"
    ipconfig /flushdns
    
    #Grabbing hosts file
    Write-Warning "grabbing hosts file"	
    New-Item -Path C:\Users\$user\Desktop\scripterino\hosts -ItemType directory
    Get-ChildItem -Path "C:\Windows\System32\drivers\etc\hosts" | Copy-Item -Destination C:\Users\$user\Desktop\scripterino\hosts


    #processes that have bigger loads
    Write-Warning "investigating shady processes"
    Get-Process | Where-Object {$_.WorkingSet -gt 20000000} > scripterino\interestingprocess.txt
    }
if ($option -eq 2) {
	#Better netstat mechanism 0.3
	#
	# Name|x| Process|x| Port|x| 
	#
	# for each process, find port, for each port make object

	$proclist = (get-nettcpconnection | ? {$_.State -eq 'Listen'}).OwningProcess

	$tcpcon = @()
	$i = 1
	foreach ($proc in $proclist) {
    	Write-Progress -Activity "TcpConnection" -Status "Filling New Object tcpcon" -PercentComplete (($i / $proclist.Count) * 100)
    	$procname = (Get-Process -PID $proc).ProcessName
        $procpath = (Get-Process -PID $proc).Path
    	$port = (Get-NetTCPConnection | ? {$_.OwningProcess -eq $proc}).LocalPort
    	$tcpcon += [PSCustomObject]@{
        	'Name' = $procname
        	'ProcessId' = $proc
        	'Port' = $port
            'Path to bin' = $procpath
    	}
        $i++
    }
    $tcpcon | sort Name | ft -AutoSize
}

if ($option -eq 3) {
	'Please enter the absolute path of the directory you wish to search(start with drive of choice ex: C:\)'
		$absolutepath = Read-Host
	'Now enter the string you wish to search for'
		$string = Read-Host 
	ls -r $absolutepath -file | % {Select-String -path $_ -pattern $string} 
} 