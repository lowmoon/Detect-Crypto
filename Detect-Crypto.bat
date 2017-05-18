@ECHO OFF

ECHO Create a list of all the shares you'll need to add later
net share >> C:\Detect-Crypto\Detect-Crypto-PreviousShares.txt

ECHO Kill all current sessions
net session /delete /y

ECHO Remove all shares
REM Copy the lines below for every share name
REM This simply removes the share so additional files cannot get encrypted
REM Does not delete the folder, just removes it from sharing
REM net share userfiles /delete /y
REM net share adminshare /delete /y

REM You will have to re-enable these Windows firewall rules later
REM Uncomment whatever zone lines are applicable if you want to deal with that shit
REM servers in domain zone
REM netsh advfirewall firewall set rule name="File and Printer Sharing (Echo Request - ICMPv4-In)" new enable=no profile=domain
REM netsh advfirewall firewall set rule name="File and Printer Sharing (Echo Request - ICMPv6-In)" new enable=no profile=domain
REM netsh advfirewall firewall set rule name="File and Printer Sharing (LLMNR-UDP-In)" new enable=no profile=domain
REM netsh advfirewall firewall set rule name="File and Printer Sharing (NB-Datagram-In)" new enable=no profile=domain
REM netsh advfirewall firewall set rule name="File and Printer Sharing (NB-Name-In)" new enable=no profile=domain
REM netsh advfirewall firewall set rule name="File and Printer Sharing (NB-Session-In)" new enable=no profile=domain
REM netsh advfirewall firewall set rule name="File and Printer Sharing (SMB-In)" new enable=no profile=domain
REM netsh advfirewall firewall set rule name="File and Printer Sharing (Spooler Service - RPC)" new enable=no profile=domain
REM netsh advfirewall firewall set rule name="File and Printer Sharing (Spooler Service - RPC-EPMAP)" new enable=no profile=domain
REM server is in private zone
REM netsh advfirewall firewall set rule name="File and Printer Sharing (Echo Request - ICMPv4-In)" new enable=no profile=private
REM netsh advfirewall firewall set rule name="File and Printer Sharing (Echo Request - ICMPv6-In)" new enable=no profile=private
REM netsh advfirewall firewall set rule name="File and Printer Sharing (LLMNR-UDP-In)" new enable=no profile=private
REM netsh advfirewall firewall set rule name="File and Printer Sharing (NB-Datagram-In)" new enable=no profile=private
REM netsh advfirewall firewall set rule name="File and Printer Sharing (NB-Name-In)" new enable=no profile=private
REM netsh advfirewall firewall set rule name="File and Printer Sharing (NB-Session-In)" new enable=no profile=private
REM netsh advfirewall firewall set rule name="File and Printer Sharing (SMB-In)" new enable=no profile=private
REM netsh advfirewall firewall set rule name="File and Printer Sharing (Spooler Service - RPC)" new enable=no profile=private
REM netsh advfirewall firewall set rule name="File and Printer Sharing (Spooler Service - RPC-EPMAP)" new enable=no profile=private
REM server is in public zone
REM netsh advfirewall firewall set rule name="File and Printer Sharing (Echo Request - ICMPv4-In)" new enable=no profile=public
REM netsh advfirewall firewall set rule name="File and Printer Sharing (Echo Request - ICMPv6-In)" new enable=no profile=public
REM netsh advfirewall firewall set rule name="File and Printer Sharing (LLMNR-UDP-In)" new enable=no profile=public
REM netsh advfirewall firewall set rule name="File and Printer Sharing (NB-Datagram-In)" new enable=no profile=public
REM netsh advfirewall firewall set rule name="File and Printer Sharing (NB-Name-In)" new enable=no profile=public
REM netsh advfirewall firewall set rule name="File and Printer Sharing (NB-Session-In)" new enable=no profile=public
REM netsh advfirewall firewall set rule name="File and Printer Sharing (SMB-In)" new enable=no profile=public
REM netsh advfirewall firewall set rule name="File and Printer Sharing (Spooler Service - RPC)" new enable=no profile=public
REM netsh advfirewall firewall set rule name="File and Printer Sharing (Spooler Service - RPC-EPMAP)" new enable=no profile=public

REM Shutdown server in 5 seconds
C:\Detect-Crypto\psshutdown.exe -f -k -t 5 -accepteula -m "Server is shutting down to protect from ransomware"

PAUSE
EXIT