
# Detect-Crypto

How to install Detect-Crypto.

1. Copy all files to C:\Detect-Crypto

2. Run Powershell as Administrator

3. cd to C:\Detect-Crypto and run the script with command:
  .\Detect-Crypto.ps1

5. Menu is shown. Choose the appropriate option number based on your deepest desires.

6. Follow prompts until main menu is shown again. Capital Q to exit. 

7. Help file is in c:\Detect-Crypto, which explains each option displayed in the main menu


filegroup.xml - file group template import file

filescreen.xml - file screen template import file 

psshutdown.exe - called by the .bat script to shutdown the host if file screen is triggered  

Detect-Crypto.ps1 - main script for deploying and updating FSRM and file screens

Detect-Crypto.bat - script FSRM executes when the file screen is triggered

ransomware_identifiers.txt - List of known ransomware extensions and file names. Add new identifiers to this list.



