# Host Security Solutions
These are a set of software applications used to monitor and detect abnormal and malicious activities within the host.
## [[Antivirus|Antivirus Software]]
Antivirus (AV) software is mainly used to monitor, detect and prevent malicious software from being executed within the host. Most antivirus software applications use well-known features, including Background scanning, Full system scans, Virus definitions. 
In the Background scanning, the AV software works in real-time and scans all open and used files in the background. The full system scan is essential when we first install the antivirus. And the Virus definitions, where AV software replies to the pre-defined virus. That's why AV software needs to update from time to time. 

It is essential to know whether antivirus exists or not, we can enumerate AV using Windows built in tools such as `wmic`
```
wmic /namespace:\\root\securitycenter2 path antivirusproduct
```
or in PowerShell
```powershell
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct
```
Windows servers may not have `SecurityCenter2` namespace, instead, it works with workstations.

## Microsoft Windows Defender
Microsoft Windows Defender is a pre-installed antivirus security tool that runs on endpoints. It uses various algorithms in the detection, such as ML, big-data analysis, in-depth threat resistance research and Microsoft cloud infrastructure. It works in three protection modes.
- **Active** mode is used where the MS defender runs as the primary AV software on the machine where it provides protection and remediation.
- **Passive** mode is when a 3rd party AV software is installed. Therefore, it works asa secondary antivirus software where it scans files and detects threats but does not provide remediation
- **Disable** mode is where it simple is disabled or uninstalled.
We can use Powershell to check the service state of MS defender
```PowerShell
Get-Service WinDefend
```
Next we can use `Get-MpComputerStatus` to get the current status of security solution elements, including Anti-spyware, AV, Real-Time protection, etc. We can pipe the output into a `select NameOfTheService` to get that specific state, in this case we are looking for `RealTimeProtectionEnabled`
```powershell
Get-MpComputerStatus
Get-MpComputerStatus | select RealTimeProtectionEnabled
```

## Host-based Firewall
It is a security tool installed and run on a host machine that can prevent and block attacker attempts. Thus making it essential to enumerate and gather details about it and its rules within the machine.
Their main purpose is to control the inbound and outbound traffic that goes through the device's interface. It protects the host from untrusted devices that are on the same network. A modern host-based firewall uses multiple levels of analyzing traffic, including packet analysis, while establishing the connection. 
A firewall acts as control access at the network layer, being capable of allowing and denying network packets. Next gen firewalls also can inspect other OSI layers, such as application layers, making it so it can detect and block SQL injections and other application-layer attacks.
We can check if the firewall profiles are enabled with 
```powershell
Get-NetFirewallProfile | Format-Table Name, Enabled
```
If we have admin privileges on the current user, then we can try to disable one or more than one firewall profile
```powershell
Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False
```
We can also learn and check the current Firewall rules, whether allowing or denying by the firewall.
```powershell
Get-NetFirewallRule | select DisplayName, Enabled, Description
```
During an engagement, we won't have a clue with what the firewall blocks. But, we can use some cmdlets to help us like `Test-NetConnection` and `TcpClient`. In this case if we have a firewall in place, and we need to test inbound connection without extra tools we can use the following. 
```powershell
Test-NetConnection -Computer 127.0.0.1 -Port 80
```
```Powershell
(New-Object System.Net.Sockets.TcpClient("127.0.0.1", "80")).Connected
```
With these, we can confirm that the inbound connection on that port is allowed or not. We can also test for remote target in the same network or domain names by specifying in the `-ComputerName` argument for the `Test-NetConnection`.

## Security Event Logging and Monitoring
By default, operating systems log various activity events in the system using log files. This event logging feature is available to the IT system and network administrators to monitor and analyze important events, whether on the host or the network side. There are various categories where the Windows operating system logs event information, including the application, system, security, services, etc. In addition, security and network devices store event information into log files to allow the system administrators to get an insight into whats going on. 
We can get a list of available event logs on the machine using
```powershell
Get-EventLog -List
```
Sometimes, this list gives us an insight into what applications and services are installed. 
In corporate networks, log agent software is installed on clients to collect and gather logs from different sensors to analyze and monitor activities within the network.
### [[Sysmon]]
Windows System Monitor ([Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)) is a service and device driver. It is one of the Microsoft Sysinternals suites. The Sysmon tool is not installed by default, but it starts logging events once installed. These logs indicators can help system admins and blue teamers to track and investigate malicious activity and help with general troubleshooting.
The following are some ways to detect whether the [[Sysmon]] is available on the machine.
We can look for a process or a service that has been named "**Sysmon**" within the current process or services
```PowerShell
Get-Process | Where-Object { $_.ProcessName -eq "Sysmon" }
```
or look for services as the following
```powershell
Get-CimInstance win32_service -Filter "Description = 'System Monitor service'"
```
```powershell
Get-Service | where-object {$_.DisplayName -like "*sysm*"}
```
It can also be done by checking the Windows registry
```powershell
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational
```
Once we detect it, we can try to find the [[Sysmon]] configuration file if we have readable permissions, to understand what is being monitored.
```powershell
findstr /si '<ProcessCreate onmatch="exclude">' C:\tools\*
```

## HIDS / HIPS
Host-Based Intrusion Detection System (HIDS). It is software that has the ability to monitor and detect abnormal and malicious activities in a host. The main purpose of HIDS is to detect suspicious activities and not to prevent them. There are two methods that the HIDS uses.
- Signature-based IDS: it looks at checksums and message authentication.
- Anomaly-based IDS: looks for unexpected activities, including abnormal bandwidth usage, protocols, and ports.
Host-Based Intrusion Prevention Systems (HIPS) secure the operating system activities of the device where they are installed. It is a detection and prevention solution against well-known attacks and abnormal behaviours. HIPS can audit the host's logs files, monitor processes, and protect system resources. HIPS combines many product features such as antivirus, behavior analysis, network, application firewall, etc.
Each also has a network-based [[Network Evasion#NIDS / NIPS|IDS/IPS]]. 

## EDR
Endpoint Detection and Threat Response (EDTR or EDR). The EDR is a cybersec solution that defends against malware and other threats. EDRs can look for malicious files, monitor endpoint, system, and network events, and record them in a database for further analysis, detection, and investigation. EDRs are the next gen of AVs and detect malicious activities on the host in real time.
EDR analyses system data and behavior for making section threats, including:
- Malware, viruses, trojans, adware, keyloggers
- Exploit chains
- Ransomware
Some common EDR software
- Cylance
- Crowdstrike
- Symantec
- SentinelOne
Even though we may deliver a payload and bypass EDR in receiving a reverse shell, the EDR is still running and it may block us from doing something else if it flags an alert.
We can use scripts for enumerating security products within the machine such as [Invoke-EDRChecker](https://github.com/PwnDexter/Invoke-EDRChecker) and [SharpEDRChecker](https://github.com/PwnDexter/SharpEDRChecker). They check for commonly used AVs, EDR, logging monitor products by checking file metadata, processes, DLL loaded into current processes, services and drivers. 
