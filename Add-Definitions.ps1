$Definitions = Get-Content ".\ransomware_identifiers.txt"
$LastFiveLines = Get-Content ".\Crypto_filegroup.xml" | Select-Object -last 5
$FirstEightLines = Get-Content ".\Crypto_filegroup.xml" | Select-Object -first 8

$FirstEightLines | Out-File ".\Crypto_filegroup.xml"

foreach ($line in $Definitions)
{
    $formattedline = $line.replace(' ','%20')
    $InsertString = "<Pattern PatternValue = '" + $formattedline + "' ></Pattern>"
    $InsertString | Out-File ".\Crypto_filegroup.xml" -append  
}

$LastFiveLines | Out-File ".\Crypto_filegroup.xml" -append