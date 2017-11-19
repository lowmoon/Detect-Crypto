<#
    .Synopsis

    Detect-Crypto will install FSRM to protect shared drives on a local or remote server. It can also enumerate and protect any drives mapped via GPO. 

    .DESCRIPTION
    
    [1] Install FSRM on Local server
        Install FSRM on the local server and import the FileGroup definitions and a screen template.
        Check to see if FSRM is already installed, install if not.
        Add SMTP server, admin email address that will be used to recieve the alerts and From address
    
    [2] Detect all Mapped drives on Domain
        Prompt for a Domain Controller, search and list all drives which have been mapped via GPO.
     
    [3] Install FSRM on Remote server
        Install FSRM and imports the FileGroup definitions and a screen template on a remote server in the domain once specified.
        Check to see if FSRM is already installed, install if not.
        Add SMTP server, admin email address that will be used to recieve the alerts and From address
    
    [4] Set Email Config 
        Change the email configuration settings for SMTP server, defualt receipt address and the From address for a local or Remote server.
        
    [5] Protect File share on Local server
        Update the lcoal FSRM server with new File Screens to protect Shared/Mapped drive folder paths.
    
    [6] Protect File Share on Remote server
        Update a Remmote FSRM server with new File Screens to protect Shared/Mapped drive folder paths.
    
    [7] Test
        Test the setup of the FSRM server, which will send an email after protecting the folder c:\RansomShareTest and adding a known bad file name.
     
    [8] Update Definitions
        Update the crypto definitions on a local or remote server. Useful when a new variant with new extensions  
        appears in the wild. Add a new definition to ransomware_identifiers.txt and choose this option.

#>

#Check for and install FSRM on remote or local server depending on your choice in the Show-Menu function
function Install-Detections 
{

  $FSRMInstalled = Get-WindowsFeature -Name FS-Resource-Manager | Select-Object Installed
  
  if ($FSRMInstalled.Installed -eq $true) 
  { 
    Write-Warning 'FSRM already installed, skipping ahead...' 
  }
  
  if ($FSRMInstalled.Installed -eq $false) 
  { 
    Install-WindowsFeature –Name FS-Resource-Manager –IncludeManagementTools -Verbose

    Write-Host ''
    Write-Host 'FSRM is Installed!' -ForegroundColor 'Green'
    Write-Host '' 
  }

  if ($Choice -eq '3')
  {
    Write-Host '3 - Install FSRM on remote server'
  }

  if ($input -eq '3')
  {
    filescrn.exe filegroup import /file:\\$Remote\c$\filegroup.xml /filegroup:"Detect-Crypto"
  }
  else
  {
    filescrn.exe filegroup import /file:$PSScriptRoot\filegroup.xml /filegroup:"Detect-Crypto"
  }

  Write-Host ''
  Write-Host 'File Group Detect-Crypto IMPORTED' -ForegroundColor 'Green'
  Write-Host ''

  if ($Choice -eq '3')
  {
    filescrn.exe template import /file:\\$Remote\c$\filescreen.xml /template:"Detect-Crypto"
  }
  else 
  {
    filescrn.exe template import /file:$PSScriptRoot\filescreen.xml /template:"Detect-Crypto"
  }

  Write-Host ''
  Write-Host 'Screen Template Detect-Crypto IMPORTED' -ForegroundColor 'Green'
  Write-Host ''
}

#Show the main menu
function Show-Menu 
{
  param(
    [string]$Title = 'Detect-Crypto'
  )
  Clear-Host
  Write-Host '---------------------------- Main Menu ------------------------------------' -ForegroundColor 'green'
  Write-Host ''
  Write-Host '[1] Install FSRM on Local server' -ForegroundColor 'green'
  Write-Host '[2] Detect all Mapped drives on Domain' -ForegroundColor 'green'
  Write-Host '[3] Install FSRM on Remote server' -ForegroundColor 'green'
  Write-Host '[4] Set Email Config on FSRM' -ForegroundColor 'green'
  Write-Host '[5] Protect File share on Local server' -ForegroundColor 'green'
  Write-Host '[6] Protect File Share on Remote server' -ForegroundColor 'green'
  Write-Host '[7] Test' -ForegroundColor 'green'
  Write-Host '[8] Update Definitions' -ForegroundColor 'green'
  Write-Host ''
  Write-Host '[9] Help'
  Write-Host '[Q] Press Q to Quit'
  Write-Host ''
}


#Install function for FSRM file screen/group and execution/notifcation configuration 
function Install-Screen 
{
  param(
    [string]$SubTitle = 'Detect-Crypto'
  )

  Write-Host '-------------------------- Protect Shared Drive ---------------------------' -ForegroundColor 'yellow'
  Write-Host ''
  Write-Host 'You will now be asked the Path of each shared drive that ' -ForegroundColor 'yellow'
  Write-Host 'requires Detect-Crypto [File Screen].  EXAMPLE:   D:\NPF' -ForegroundColor 'yellow'
  Write-Host ''
  Write-Host 'Here is a list of shares on current server' $env:computername

  Get-WmiObject -Class 'Win32_Share' | Format-Table -AutoSize

  do 
  {
    do 
    { $value1 = Read-Host -Prompt 'How many shares require Detect-Crypto'
      if ($value1 -notin (0..100)) 
      { 
        Write-Warning 'Use a number' 
      }
    }
    while ((1..100) -notcontains $value1)


    foreach ($i in 1..$value1) 
    {

      Write-Host ''
      $Share1 = Read-Host -Prompt 'Enter Share Path'
      $RescueCommands = Get-Content "C:\Detect-Crypto\Detect-Crypto.bat" -Raw
      $BatchFilename = New-Item "C:\Windows\Scripts\Detect-Crypto-$env:computername.bat" -Type file -Force -Value "$RescueCommands"
      $fileGroupName = 'Detect-Crypto'
      $cmdConfFilename = "$env:Temp\fsrm-cmdnotify.txt"
      $cmdConfFilename2 = "$env:Temp\fsrm-cmdnotify2.txt"

#Config for execution action in FSRM
       $cmdConf = @"
Notification=C
RunLimitInterval=0
Command=$batchFilename
Arguments=[Source Io Owner]
MonitorCommand=Enable
Account=LocalSystem
"@


#Config for notification action in FSRM     
      $cmdConf2 = @"
Notification=m
To=[Admin Email]
From=$Fromaddress
Subject=URGENT - Ransomware DETECTED on [Server]
Message=User [Source Io Owner] attempted to save [Source File Path] to [File Screen Path] on the [Server] server. This file is in the [Violated File Group] file group, which is not permitted on the server.. \
\
WARNING: All user sessions are disconnected and server is shutdown. \
\
See Help file on server [Server] - C:\Detect-Crypto
"@

      $cmdConf | Out-File $cmdConfFilename
      $cmdConf2 | Out-File $cmdConfFilename2

      filescrn Screen Add /Path:$Share1 /Type:Passive /Add-Filegroup:"Detect-Crypto" "/Add-Notification:C,$cmdConfFilename" "/Add-Notification:m,$cmdConfFilename2"

    }

    [console]::ResetColor()
    Write-Host ''
    Write-Host 'Do you need to add any more Shares' -NoNewline
    Write-Host ' [yes]' -ForegroundColor Yellow -NoNewline
    Write-Host ' or' -NoNewline
    Write-Host ' [no (Default)]' -ForegroundColor Yellow -NoNewline
    $continue = Read-Host -Prompt ' '
    [console]::ResetColor()
  }
  while ($continue -match 'yes|y')
}

#Tests FSRM by creating a folder, sharing the folder, and creating a known bad file with malicious title
function Test-Crypto 
{

  Write-Host 'This test will:' -ForegroundColor 'yellow'
  Write-Host 'Create temp share [C:\RansomShareTest]' -ForegroundColor 'yellow'
  Write-Host 'Create a File screen for the test share in FSRM' -ForegroundColor 'yellow'
  Write-Host 'Create a txt file named [+recover+.txt]' -ForegroundColor 'yellow'
  Write-Host 'The Share and File screen will be removed at end of test' -ForegroundColor 'yellow'
  Write-Host ''

  Write-Host 'Do you want to run the TEST' -NoNewline
  [console]::ForegroundColor = 'yellow'
  Write-Host ' [yes]' -NoNewline
  [console]::ResetColor()
  Write-Host ' or' -NoNewline
  [console]::ForegroundColor = 'yellow'
  Write-Host ' [no]' -NoNewline
  [console]::ResetColor()
  $test = Read-Host -Prompt ' '
  [console]::ResetColor()

  if ($test -match 'yes|y') {

      New-Item C:\RansomShareTest -Type directory
      net.exe share RansomShareTest=c:\RansomShareTest /remark:"Test Share"

      $TestShare = 'C:\RansomShareTest'
      $RescueCommands = Get-Content "C:\Detect-Crypto\Detect-Crypto.bat" -Raw
      $BatchFilename = New-Item "C:\Windows\Scripts\Detect-Crypto-$env:computername.bat" -Type file -Force -Value "$RescueCommands"
      $fileGroupName = 'Detect-Crypto'
      $cmdConfFilename = "$env:Temp\fsrm-cmdnotify.txt"
      $cmdConfFilename2 = "$env:Temp\fsrm-cmdnotify2.txt"


#Config for execution action in FSRM
       $cmdConf = @"
Notification=C
RunLimitInterval=0
Command=$batchFilename
Arguments=[Source Io Owner]
MonitorCommand=Enable
Account=LocalSystem
"@

#Config for notifcation action in FSRM
      $cmdConf2 = @"
Notification=m
To=[Admin Email]
From=$Fromaddress
Subject=URGENT - Ransomware DETECTED on [Server]
Message=User [Source Io Owner] attempted to save [Source File Path] to [File Screen Path] on the [Server] server. This file is in the [Violated File Group] file group, which includes names and extensions of known ransomware. \
\
WARNING: All user sessions have been disconnected and the server is shutdown.
\
For more info on how to run this service, see the Help file on server [Server] in C:\Detect-Crypto
"@

      $cmdConf | Out-File $cmdConfFilename
      $cmdConf2 | Out-File $cmdConfFilename2


      filescrn Screen Add /Path:$TestShare /Type:Passive /Add-Filegroup:"Detect-Crypto" "/Add-Notification:C,$cmdConfFilename" "/Add-Notification:m,$cmdConfFilename2"

    [console]::ForegroundColor = 'gray'

    New-Item $TestShare\+Recover+.txt -Type File

    filescrn screen delete /path:C:\RansomShareTest /quiet
 
    net share RansomShareTest /delete

    Remove-Item C:\RansomShareTest -Recurse

     [console]::ResetColor()
    Write-Host ''
    Write-Host 'You should now recieve an email alert from' -ForegroundColor 'yellow' -NoNewline
    Write-Host " $Fromaddress " -ForegroundColor 'white' -NoNewline
    Write-Host 'advising of a' -ForegroundColor 'yellow' -NoNewline
    Write-Host ' +recover+.txt' -ForegroundColor 'white' -NoNewline
    Write-Host ' file in' -ForegroundColor 'yellow' -NoNewline
    Write-Host ' C:\RansomShareTest' -ForegroundColor 'white' -NoNewline
    Write-Host ''

  }
}

#Test for connection to remote machine prior to FSRM install
function Get-Remote 
{

  Write-Host ''
  Write-Host '[Q] Return to Main Menu'
  do 
  {
    Write-Host ''
    $Global:Remote = Read-Host 'Name of Remote Server'
    $Error.Clear()

    if ($Remote -notlike 'q') 
    {
      $Connection = Test-Connection -ComputerName $Remote -Count 1
    }
    else {}
  }
 
  while (($Connection -eq $null) -or ($Connection -eq $false) -and ($Remote -notlike 'q'))

  $Error.Clear()
}

#Set email server and to/from address configuration in  FSRM
function Set-Email 
{

  $smtp = Read-Host 'Set SMTP server'
  $smtp = $smtp.Replace(' ' , '')
  Set-FsrmSetting -SmtpServer $smtp
  Set-FsrmSetting -CommandNotificationLimit 2 -EmailNotificationLimit 2 -EventNotificationLimit 2

  
  do
  {
     $Global:Adminaddress = Read-Host 'Default "To" address'
     $Global:Adminaddress = $Global:Adminaddress.Replace(' ' , '')
     
     if($Adminaddress -notmatch "@")
     { 
        Write-Warning 'Not valid email address'
     }
     else 
     {
        Set-FsrmSetting -AdminEmailAddress $Adminaddress
     }
   }
  while(($Adminaddress -notmatch "@") -and ($Adminaddress -notlike "q"))

  


  do
  {
     $Global:Fromaddress = Read-Host 'Enter "From" email address'
     $Global:Fromaddress = $Global:Fromaddress.Replace(' ' , '')
     
     if($Fromaddress -notmatch "@")
     { 
        Write-Warning 'Not valid email address'
     }
     else
     {
        Set-FsrmSetting -FromEmailAddress $Fromaddress
     }
   }
  while(($Fromaddress -notmatch "@") -and ($Adminaddress -notlike "q"))

}

#Enumerate mapped drives dictated by group policy
function Get-MappedDrives
{

try
{
Import-Module GroupPolicy -ErrorAction Stop
}
catch
{
throw "Module GroupPolicy not Installed"
}
        $GPO = Get-GPO -All
 
        foreach ($Policy in $GPO)
        {
 
                $GPOID = $Policy.Id
                $GPODom = $Policy.DomainName
                $GPODisp = $Policy.DisplayName
 
                 if (Test-Path "\\$($GPODom)\SYSVOL\$($GPODom)\Policies\{$($GPOID)}\User\Preferences\Drives\Drives.xml")
                 {
                     [xml]$DriveXML = Get-Content "\\$($GPODom)\SYSVOL\$($GPODom)\Policies\{$($GPOID)}\User\Preferences\Drives\Drives.xml"
 
                            foreach ( $drivemap in $DriveXML.Drives.Drive )
                                {
                                    New-Object PSObject -Property @{
                                    GPOName = $GPODisp
                                    DriveLetter = $drivemap.Properties.Letter + ":"
                                    DrivePath = $drivemap.Properties.Path
                                    DriveAction = $drivemap.Properties.action.Replace("U","Update").Replace("C","Create").Replace("D","Delete").Replace("R","Replace")
                                    DriveLabel = $drivemap.Properties.label
                                    DrivePersistent = $drivemap.Properties.persistent.Replace("0","False").Replace("1","True")
                                    DriveFilterGroup = $drivemap.Filters.FilterGroup.Name}
                                }
                }
        }
  }

#Update FSRM with new definitions 
#I should really automate this to pull new defitions from various sources (experiant, etc.)
function Update-Definition 
{

  Write-Host ''
  Write-Host 'This will update the file group/screen with new definitions.'   -ForegroundColor Green
  Write-Host ''
  Write-Host 'New definitions are pulled from the ransomware_identifiers.txt file. Please add new defitions to that .txt file.'  -ForegroundColor Green
  Write-Host ''
  Write-Host 'EXAMPLE: .*zepto,*virus*,fixyourfiles.* '   -ForegroundColor Green
  Write-Host ''
  
  while($Pattern -notlike 'q')
  {
     $Error.Clear()
     $Pattern = Read-Host 'Ready to Update defintions? [q to quit, enter to continue]'
  
     if ($Pattern -notlike 'q') 
     {

        $Definitions = Get-Content "C:\Detect-Crypto\ransomware_identifiers.txt"
        $LastFiveLines = Get-Content ".\filegroup.xml" | Select-Object -last 5
        $FirstEightLines = Get-Content ".\filegroup.xml" | Select-Object -first 8
        $FirstEightLines | Out-File ".\filegroup.xml"

        foreach ($item in $Definitions) 
        {

           $Group = Get-FsrmFileGroup "Detect-Crypto"
           $List = $Group.IncludePattern + $Item

           Set-FsrmFileGroup -Name 'Detect-Crypto' -IncludePattern @($List)
    
          $formattedline = $item.replace(' ','%20')
          $InsertString = "<Pattern PatternValue = '" + $formattedline + "' ></Pattern>"
          $InsertString | Out-File -append ".\filegroup.xml"  
          
        }

        $LastFiveLines | Out-File -append ".\filegroup.xml" 
        Write-Host ''
        Write-Host 'Definitions Added'  -ForegroundColor Green
        Write-Host ''
      }  
      else{}
  }
  Pause
}

function InvokeUpdate-Email
{

$Computer = Get-ADComputer -Filter {OperatingSystem -Like "Windows *server*"} -Properties Name | Select-Object -ExpandProperty Name | Where-Object { Test-Connection -ComputerName $PSItem -BufferSize 1 -Count 1 -TimeToLive 1 -ErrorAction SilentlyContinue }
$Computers = Invoke-Command $Computer -Scriptblock {Get-WindowsFeature -Name FS-Resource-Manager | where-object {$_.Installed -eq $true}}

$Session = New-PSSession -ComputerName $Computers.PSComputername

$smtp = Read-Host 'Smtp server'
$smtp = $smtp.Replace(' ' , '')

   do
   {
     $Adminaddress = Read-Host 'Default recipient [Admin] address'

     if(($Adminaddress -notmatch "@") -or ([string]::IsNullOrWhiteSpace($Adminaddress)))
     { 
        Write-Warning 'Not valid email address'
     }

     else 
     {
        $Adminaddress = $Adminaddress.Replace(' ' , '')
     }
   }
  while($Adminaddress -notmatch "@")

  do
  {
     $Fromaddress = Read-Host 'Enter [From] email address'
     if($Fromaddress -notmatch "@")
     { 
        Write-Warning 'Not valid email address'
     }
     else
     {
        $Fromaddress = $Fromaddress.Replace(' ' , '')
     }
  }
  while($Fromaddress -notmatch "@")

    $scriptBlock = {
        param($Script3,$Script4,$Script5)
        Set-FsrmSetting -SmtpServer $Script3
        Set-FsrmSetting -CommandNotificationLimit 2 -EmailNotificationLimit 2 -EventNotificationLimit 2
        Set-FsrmSetting -AdminEmailAddress $Script4
        Set-FsrmSetting -FromEmailAddress $Script5
        Write-Output "Settings changed on $env:COMPUTERNAME"
    }


    Invoke-Command -Session $Session -ScriptBlock $scriptBlock -ArgumentList $smtp, $Adminaddress, $Fromaddress
}

function Get-DCCommand
{
        do
        {
        $error.clear()
        $Global:DC = Read-Host 'Name of Domain Controller'
        Get-PSSession | Remove-PSSession 

        if ($DC -notlike 'q')
        {   
            $S = New-PSSession $DC
            Import-PSSession -CommandName Get-AdComputer -Session $S

        }
        else {}
        }
        while (($Error.count -gt 0) -or ($DC -like $null))

}

function InvokeUpdate-Definition
{

$Session = New-PSSession -ComputerName $Using:Computers.PSComputername

    $Pattern = Read-Host 'Ready to Update defintions? [q to quit, enter to continue]'
    $Definitions = Get-Content "C:\Detect-Crypto\ransomware_identifiers.txt"
    $scriptBlock = {
        param($Definitions)

        
        foreach ($item in $Definitions) 
        {

           $Group = Get-FsrmFileGroup "Detect-Crypto"
           $List = $Group.IncludePattern + $Item

           Set-FsrmFileGroup -Name 'Detect-Crypto' -IncludePattern @($List)
           
          $LastFiveLines = Get-Content ".\filegroup.xml" | Select-Object -last 5
          $FirstEightLines = Get-Content ".\filegroup.xml" | Select-Object -first 8

          $FirstEightLines | Out-File ".\filegroup.xml"
    
          $formattedline = $item.replace(' ','%20')
          $InsertString = "<Pattern PatternValue = '" + $formattedline + "' ></Pattern>"
          $InsertString | Out-File ".\filegroup.xml" -append  
          $LastFiveLines | Out-File ".\filegroup.xml" -append
        }

        Write-Host ''
        Write-Host 'Definitions Added'  -ForegroundColor Green
        Write-Host ''
        ## UPDATE THE FILEGROUP WITH EACH ITEM
        Set-FsrmFileGroup -Name 'Detect-Crypto' -IncludePattern @($List)


        Write-Output "Settings changed on $env:COMPUTERNAME"
        
    }

    Invoke-Command -Session $Session -ScriptBlock $scriptBlock -ArgumentList $Pattern

}

do
{
  Show-Menu

  $input = Read-Host 'Please make a selection'
  switch ($input)
  {
    '1' {
      
      Clear-Host

      $SubMenu = '--------------------- Detect-Crypto Install [Local] -----------------------'
      Write-Host '--------------------- Detect-Crypto Install [Local] -----------------------' -ForegroundColor 'green'
      Write-Host ''

      Install-Detections
      Set-Email

      Clear-Host
      
      Write-Host $SubMenu -ForegroundColor 'green'

      Install-Screen
      
      Write-Host ''
      Write-Host '--------------------- Detect-Crypto Install [Complete] -----------------------' -ForegroundColor 'green'
      Write-Host ''

      Pause

    }
    '2' {
      Clear-Host

      Write-Host '-------------------------- Mapped Drive GPOs -----------------------------' -ForegroundColor green
      Write-Host '[Q] Press Q to Quit' -ForegroundColor 'yellow'
      Write-Host ''

      do {
        
        $DC = Read-Host 'Name of Domain Controller'
        if ($DC -eq 'q') {}

        else {
          $Error.Clear()

          Invoke-Command -ComputerName $DC -ScriptBlock ${Function:Get-MappedDrives} | select drivePath, DriveLabel, DriveLetter | Sort DriveLetter | Format-Table
        }
      }
      while (($Error.Count -eq 1) -and ($DC -notlike 'q'))

      Pause
    }
    '3' {
      Clear-Host

      Write-Host '-------------------- Detect-Crypto Install [Remote] -----------------------' -ForegroundColor Green

      Get-Remote

      if ($Remote -notlike 'q') 
      {

        New-Item -ItemType Directory \\$Remote\c$\Detect-Crypto -Force
        Copy-Item $PSScriptRoot\filegroup.xml \\$Remote\c$\filegroup.xml -Verbose -Force
        Copy-Item $PSScriptRoot\filescreen.xml \\$Remote\c$\filescreen.xml -Verbose -Force
        Copy-Item $PSScriptRoot\Detect-Crypto.bat \\$Remote\c$\Detect-Crypto.bat -Verbose

        Write-Host ''

        $Global:Choice = '3'

        $RemoteInstall = Read-Host 'Install FSRM, File Screens and Protect server Shares [y] or [n] ?'
        if ($RemoteInstall -match 'yes|y')
        { 
            Invoke-Command -ComputerName $Remote -ScriptBlock ${Function:Install-Detections}
            $Global:Choice = $Null

            Remove-Item \\$Remote\c$\filegroup.xml -Verbose -Force
            Remove-Item \\$Remote\c$\filescreen.xml -Verbose -Force
          
            Invoke-Command -ComputerName $Remote -ScriptBlock ${Function:Set-Email}

            Clear-Host

            Write-Host "------------------ Detect-Crypto Install [$Remote] ----------------------" -ForegroundColor Green
        
            Invoke-Command -ComputerName $Remote -ScriptBlock ${Function:Install-Screen}
          
            Remove-Item \\$Remote\c$\Detect-Crypto.bat -Verbose -Force

            Write-Host ''
            Write-Host '--------------------- Detect-Crypto Install [Complete] -----------------------' -ForegroundColor 'green'
            Write-Host ''    
        }
      }
      else {}

      Pause

    }
    '4' {
      Clear-Host

      Write-Host '------------------------ Detect-Crypto [Eamil Config]---------------------------' -ForegroundColor 'green'
      Write-Host ''
      Write-Host '[A] Local Email Config' -ForegroundColor 'green'
      Write-Host '[B] Remote Email Config' -ForegroundColor 'green'
      Write-Host '[C] Update all FSRM Servers' -ForegroundColor 'green'
      Write-Host ''
      Write-Host '[Q] Return to Main Menu'
      Write-Host ''

      $input3 = Read-Host 'Please make a selection'

      switch ($input3) {

        'A' {

          Set-Email
        }
        'B' {

          Get-Remote
          Invoke-Command -ComputerName $Remote ${Function:Set-Email}

        }
        'C' {
        InvokeUpdate-Email

        Pause
        }

      }


    }
    '5' {
      Clear-Host

      Write-Host '---------------------- Protect Shared Drive [Local] ------------------------' -ForegroundColor green
      
      Install-Screen

      Pause
    }
    '6' {
      Clear-Host

      Write-Host '------------------ Detect-Crypto Install [Remote] -----------------------' -ForegroundColor Green
      Write-Host ''

      Get-Remote

      Clear-Host

      Write-Host "------------------ Detect-Crypto Install [$Remote2] ----------------------" -ForegroundColor Green

      if ($Remote -notlike 'q') 
      {
        Invoke-Command -ComputerName $Remote -ScriptBlock ${Function:Install-Screen}
   
      Pause
      }

    }
    '7' {
      Clear-Host

      Write-Host '------------------------- Detect-Crypto Test ------------------------------' -ForegroundColor 'green'
      Write-Host ''
      Write-Host '[A] Local Test' -ForegroundColor 'green'
      Write-Host '[B] Remote Test' -ForegroundColor 'green'
      Write-Host ''
      Write-Host '[Q] Return to Main Menu'
      Write-Host ''

      $input2 = Read-Host 'Please make a selection'
      switch ($input2) {

        'A' {
          Clear-Host

          Write-Host '---------------------- Detect-Crypto Test [Local]--------------------------' -ForegroundColor 'green'
          Write-Host ''
          
          Test-Crypto

          Pause

        }
        'B' {
          Clear-Host

          Write-Host '------------------- Detect-Crypto Test [Remote]-----------------------' -ForegroundColor 'green'
          Write-Host ''

          Get-Remote

          Clear-Host

          Write-Host "--------------------- Detect-Crypto Test [$Remote]--------------------------" -ForegroundColor 'green'
          Write-Host ''

          if ($Remote -notlike 'q')
          {
            Invoke-Command -ComputerName $Remote -ScriptBlock ${Function:Test-Crypto}

          Pause
          }

        }
        'q' {

        }

      }

    }
    '8' {
      Clear-Host

      Write-Host '------------------------ Detect-Crypto Definitions ------------------------' -ForegroundColor 'green'
      Write-Host ''
      Write-Host '[A] Update Definitions on Local Server' -ForegroundColor 'green'
      Write-Host '[B] Update Definitions on Remote Server' -ForegroundColor 'green'
      Write-Host '[C] Update all FSRM servers'    -ForegroundColor 'green'
      Write-Host ''
      Write-Host '[Q] Return to Main Menu'
      Write-Host ''
      $input3 = Read-Host 'Please make a selection'
      switch ($input3) {

        'A' {
          
          Update-Definition
        }
        'B' {

          Clear-Host

          Write-Host '---------------------- Detect-Crypto Definitions [Remote]------------------' -ForegroundColor 'green'
          Write-Host ''

          Get-Remote

          Invoke-Command -ComputerName $Remote ${Function:Update-Definition}

        }
        'C' {

        Write-host ''
        Write-Host 'Get Servers with FSRM Install' -ForegroundColor blue
        Write-host ''

        Get-DCCommand
        $Error.Clear()

        If (($DC -notlike 'q') -and ($DC -notlike $Null)){

          $Error.Clear()

        $ComputerList = (Get-ADComputer -Filter {OperatingSystem -Like "Windows *server*"}).Name|
        Where-Object { Test-Connection -ComputerName $PSItem -BufferSize 1 -Count 1 -TimeToLive 80 -ErrorAction SilentlyContinue }

        

        $Results=Invoke-Command $ComputerList -Scriptblock {Get-WindowsFeature -Name FS-Resource-Manager | where-object {$_.Installed -eq $true}}

        Clear-Host

        Write-Host '---------------------- Detect-Crypto Definitions [ALL]---------------------' -ForegroundColor 'green'

        Write-Host ''
        Write-Host 'Update Definitions on all servers with FSRM Install' -ForegroundColor Blue


          Write-Host ''
          Write-Host 'This will update the file group/screen with new definitions.'   -ForegroundColor Green
          Write-Host ''
          Write-Host 'New definitions are pulled from the ransomware_identifiers.txt file. Please add new defitions to that .txt file.'  -ForegroundColor Green
          Write-Host ''
          Write-Host 'EXAMPLE: .*zepto,*virus*,fixyourfiles.* '   -ForegroundColor Green
          Write-Host ''

        
        $Pattern = Read-Host 'Ready to Update defintions? [q to quit, enter to continue]'
        $Definitions = Get-Content "C:\Detect-Crypto\ransomware_identifiers.txt"
        foreach($computer in $Results)
        {
            $Session = New-PSSession -ComputerName $computer.PSComputername

            Invoke-Command -Session $Session -ScriptBlock `
            {
                param($Definitions)

                foreach ($item in $Definitions) 
                    {

                        $Group = Get-FsrmFileGroup "Detect-Crypto"
                        $List = $Group.IncludePattern + $Item

               ## UPDATE THE FILEGROUP WITH EACH ITEM
                        Set-FsrmFileGroup -Name 'Detect-Crypto' -IncludePattern @($List)

                        Write-Output "Settings changed on $env:COMPUTERNAME"
                        Write-Host ''
                    }
            } -ArgumentList $Pattern

        }  
  

        $Session|Remove-PSSession   
        Remove-PSSession -ComputerName $DC
        }



      Pause
        }

        'q'{}
      }

    }

    '9' {
      Clear-Host

      get-help Install-Detections -Showwindow

    }
    'q' {

      return
    }

  }

}
until ($input -eq 'q')
