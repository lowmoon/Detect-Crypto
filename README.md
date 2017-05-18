How to install Detect-Crypto.

1. Copy all files to C:\Detect-Crypto

2. Run Powershell as Administrator

3. Run the command below to allow the script to be run if you have an execution policy in place:
Set-ExecutionPolicy -ExecutionPolicy Unrestricted

4. cd to C:\Detect-Crypto and run the script with command below:
.\Detect-Crypto.ps1

5. Menu is shown. Choose appropriate option number.

6. Follow prompts until main menu is shown again. Capital Q to exit. 

7. Help file is in c:\Detect-Crypto, which explains each option displayed in the main menu

8. Once installation complete, run the command below to stop unsigned scripts if you wish:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned
