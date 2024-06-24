# System
One command that can give us detailed information about the system, such as build number and installed patches
```powershell
systeminfo
```

We can check installed updates using 
```powershell
wmic qfe get Caption,Description
```
This information will give us an idea of how quickly systems are being patched.

We can check the installed and started Windows services using 
```powershell
net start
```

If we are interested in installed apps, we can use
```powershell
wmic product get name,version,vendor
```


# Users
To know what we are capable we can use
```powershell
whoami /priv
```
Moreover, we can check which groups we belong to with
```powershell
whoami /groups
```

We can view users by running
```powershell
net user
```
We can also discover available groups inside a Windows Domain Controller using
```powershell
net group
```
or otherwise
```powershell
net localgroup
```
We can list the users that belong to a certain group by adding it to the prior command like 
```powershell
net localgroup administrators
```

To see the local setting on a machine we can use
```powershell
net accounts
```
moreover, we can append `/domain` to check if the machine belongs to a domain. This could help us to learn about password policy, such as minimum length, max password age, lockout duration, etc.

# Networking
We can use the `ipconfig` command to learn about the system network configuration. If we want to know all network-related settings, we can use 
```powershell
ipconfig /all
```

We can also use `netstat` to get various information such as which ports the system is listening on, which connections are active, and what is using them. We can also use the following flags `-abno` to show all listening ports and active connections, find the binary involved in a connection, avoid resolving IP addresses and port numbers and display the PID.

We can also use `arp -a` to help us discover other systems in the same LAN that recently communicated with the system. This communication can be an attempt to connect or even a simple ping.

# DNS
If we can get a copy of all the records that a DNS server is responsible for answering, which can help us discover hosts. 
One easy way to try DNS zone transfer is via the [[Reconnaissance#nslookup/dig|dig]] command. Depending on the NDS server configuration, DNS zone transfer might be restricted. If it is not restricted it should be achievable using
```AttackerBox
dig -t AXFR DOMAIN_NAME @DNS_SERVER
```
The `-t AXFR` indicates that we are requesting a zone transfer, while `@` precedes the `DNS_SERVER` that we want to query regarding the records related to the specified `DOMAIN_NAME`.

# [[Network Services Vulnerabilities#SMB|SMB]]
We can check shared folders using 
```Powershell
net share
```

# SNMP
Simple Network Management Protocol (SNMP) was designed to help collect information about different devices on a network. It **lets us know about various network events**, from a server with a faulty disk to a printer out of ink. Consequently, SNMP can hold a trove of information for us. One simple tool to query related to SNMP is `snmpcheck`. The syntax is quite simple
```AttackerBox
snmpcheck IP -c COMMUNITY_STRING
```
if this doesn't work we can also try `snmp-check` and `snmpwalk`

# Systinternals Suite
The [[Sysinternals]] suite is a group of CLI and GUI utilities and tools that provide information about various aspects related to the Windows system. 

|Utility Name|Description|
|---|---|
|Process Explorer|Shows the processes along with the open files and registry keys|
|Process Monitor|Monitor the file system, processes, and Registry|
|PsList|Provides information about processes|
|PsLoggedOn|Shows the logged-in users|

# [[Process Hacker]]
Another efficient and reliable MS Windowds GUI tool that lets us gather information about running processes. It gives us detailed information regarding running processes and related active network connections, also, it gives us insight into system resource utilization from CPU and memory to disk and network.

# GhostPack Seatbelt
[Seatbelt](https://github.com/GhostPack/Seatbelt), part of the GhostPack collection, is a tool written in C#. It is not officially released in binary form, therefore we need to compile it using MS visual studio.
