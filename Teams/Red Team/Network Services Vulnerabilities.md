
| Protocol | TCP Port | Application(s) | Data Security        |
| -------- | -------- | -------------- | -------------------- |
| FTP      | 21       | File Transfer  | Cleartext            |
| HTTP     | 80       | Worldwide Web  | Cleartext            |
| IMAP     | 143      | Email (MDA)    | Cleartext            |
| POP3     | 110      | Email (MDA)    | Cleartext            |
| SMTP     | 25       | Email (MTA)    | Cleartext            |
| Telnet   | 23       | Remote Access  | Cleartext            |
| SMB      | 445/139  | File Transfer  | Cleartext by default |
| SSH      | 22       | Remote Access  | Encrypted            |
| NFS      | 111/2049 | File Transfer  | Cleartext            |
| MySQL    | 3306     | Database       | Cleartext by default |
| RDP      | 3389     | Remote Desktop | Encrypted            |


# SMB
Server Message Block protocol is a client-server communication protocol used for sharing access to files, printers, serial ports and other resources on a network.
Servers make files systems and other resources available to clients on the network. Client computers may have their own hard disks, but they also want access to the shared files systems and printers on the servers.
The SMB protocol is known as a response-request protocol, meaning that it transmits multiple messages between the client and server to establish a connection. Clients connect to servers using TCP/IP, NetBEUI or IPX/SPX. 

Once they have established a connection, clients can then send commands to the server that allow them to access shares, open files, read and write files, and manipulate in general the file system.

MS windows operating systems since windows 95 have included client and server SMB protocol support. Samba, an open source server that supports the SMB protocol was released for Unix systems.
## Enumerating
Typically, there are SMB share drives on a server that can be connected to and used to view or transfer files. SMB can often be a great starting point for an attacker looking to discover sensitive information.
Then a port scan is a must, to find out as much information about the target machine as we can.
[[Enum4Linux]] is a tool used to enumerate SMB shares on both Windows and Linux systems. It is basically a wrapper around the tools in the Samba package and makes it easy to quickly extract information from the target about SMB.
```
enum4linux [options] IP
```
## Exploiting
Although there are vulnerabilities for RCE by exploiting SMB, we are more likely to encounter a situation where the best way into a system is due to misconfigurations in the system. One common misconfiguration is anonymous SMB share access.
Because we are trying to access an SMB share we need a client to access resources on servers. For this we can use `smbclient` as it is part of the default samba suite.
```Shell
smbclient //IP/SHARE -U NAME -p PORT
```
From here we log into the SMB share if it has anonymous read access and we can investigate from here to try and escalate.

# Telnet
Telnet is an application protocol which allows us to connect to and execute commands on a remote machine that's hosting a telnet server. The telnet client will establish a connection with the server. The client will then become a virtual terminal, allowing us to interact with the remote host.
The user connect to the server by using the Telnet protocol, with the `telnet` command, then it can execute commands on the server by using specific Telnet commands in the prompt. To connect 
```Shell
telnet IP PORT
```
It sends all messages in clear text and has no security mechanism, due to this it has been replaced by [[SSH]] in most implementations.
## Enumeration
Not much happens in this stage, we start with a port scan and from here we can go ahead and connect trough the telnet protocol with the port found. 
## Exploiting
Like other services Telnet has a few CVE's that can take us to RCE, but like the others it is most likely that we can escalate due to misconfigurations like not asking for credentials.
One problem that we may encounter is that the prompt does note tells us if our commands are being ran. One way to check for it is set up [[tcpdump]] to listen for ICMP traffic, which `ping` operates on
```shell
tcpdump ip proto \\icmp -i tun0
```
from here we can try to run various reverse shells with our listener active to see if we can get one to run.

# FTP
File Transfer Protocol uses a client-server model and relays commands and data in a very efficient way. A typical FTP session operates using two channels
- a command channel
- a data channel
As their names indicate, the command channel is used for transmitting commands as well as replies to those commands, while the data channel is used for transferring data.
The client initiates a connection with the server, the server validates whatever login credentials are given and then opens the session.

The FTP server may support either Active or Passive connections or both.
- In an Active FTP connection, the client opens a port and listens. The server is required to actively connect to it.
- In a Passive FTP connection, the server opens a port and listens and the client connects to it.

## Enumerating
Port scanning, and from here we can start by logging in to a FTP server with the FTP client `ftp`
Also, Some vulnerable versions of `in.ftpd` and some other FTP server variants return different responses to the `cwd` command for home directories which exist and those that don't. This can be exploited because we can issue `cwd` commands before authentication, and if there's a home directory. While this [bug](https://www.exploit-db.com/exploits/20745) is mainly found within legacy systems, it's still worth knowing. 
We can also connect through [[Netcat]] by specifying the port
```
nc IP 21
```

## Exploiting
All the data in both the command and data channels is unencrypted, so it can be intercepted and read. Trying to use a MITM tactic could work to snatch credentials or other sensitive data. But it also allows us to bruteforce passwords.
[[Hydra]] in this case may be our go to buddy

# NFS
Network File System protocol allows a system to share directories and files with others over a network. I does this by mounting all, or a portion of a file system on a server. The portion of the file system that is mounted can be accessed by clients with whatever privileges are assigned to each file.
First, the client will request to mount a directory from a remote host on a local directory. The mount service will then try to connect to the relevant mount daemon using RPC.
The server checks if the user has permission to mount whatever directory has been requested. It will then return a file handle which uniquely identifies each file and directory that is on the server. If someone wants to access a file using NFS, an RPC call is placed to NFSD (NFS daemon) on the server which takes the following parameters:
- The file handle
- The name of the file to be accessed
- The user's UID
- The user's GUID
Which are used to determine access rights to the specified file.
We can use it to transfer files between computers running Windows and other systems like UNIX, MacOS, or Linux.
A computer running Windows Server can act as an NDS file server for other non-Windows clients. Likewise, NFS allows a windows-based computed running Windows Server to access files stored on a non-Windows NFS server.
## Enumerating
For machines using NFS it is important to have the `nfs-common` package installed as it comes with various programs like: `lockd`, `stad`, `showmount`, `nfsstat`, `gssd`, `idmapd`, and `mount.nfs`. Our main focus relies on `showmount` and `mount`, as these are the ones that are most useful to us when extracting information from the NFS share.
Our client's system needs a directory where all the content shared by the host server in the export folder can be accessed. We can create this folder anywhere on the system, and use the `mount` command to connect the NFS share to the mount point
```shell
mount -t nfs IP:SHARE /local/dir/ -nolock
```

| Option     | Function                                                        |
| ---------- | --------------------------------------------------------------- |
| `-t nfs`   | Type of device to mount, in this case NFS                       |
| `IP:SHARE` | IP address of target and the name of the share we wish to mount |
| `-nolock`  | Specifies no to use NLM locking                                 |
## Exploiting
[[Privilege Escalation - Linux#NFS|For NFS explotation]]

# SMTP
Simple Mail Transfer Protocol, it is utilised to handle the sending of emails. In order to support email services, a protocol pair is required, comprising of SMTP and POP/IMAP. Together the allow the user to send outgoing mail and retrieve incoming mail respectively.
The SMTP server performs these basic functions:
- It verifies who is sending the emails through the SMTP server.
- It sends the outgoing mail
- If the  outgoing mail can't be delivered it sends the message back to the sender.
Now, the Post Office Protocol (POP) and the Internet Message Access Protocol (IMAP), are both email protocols who are responsible for the transfer between a client and a mail server. The main differences is in POP's more simplistic approach of downloading the inbox from the mail server, to the client. Where IMAP will synchronise the current inbox, with new mail on the server, downloading anything new. This means that changes to the inbox made on one computer, over IMAP, will persist if we then synchronise the inbox from another computer. The POP/IMAP server is responsible for fulfilling this process.
SMTP Server software is available on windows server platforms and there are many other variants of SMTP available to run on Linux.

## Enumerating
Poorly configured or vulnerable mail servers can often provide an initial foothold into a network, but prior to launching an attack, we want to fingerprint the server to make our targeting as precise as possible. For this we can use the `smtp_version` module in [[Metasploit]] to do this.

The SMTP service has two internal commands that allow the enumeration of users: `VRFY` (Confirms the names of valid users) and `EXPN` (which reveals the actual addresses of user's aliases and lists of mailing lists). With these commands we can reveal a list of valid users.
We can do this manually, over a telnet connection, but, we can also use [[Metasploit]] which provides a module called `smtp_enum`. It works with a simple host and a wordlist containing usernames to enumerate.

Other alternatives besides [[Metasploit]], can be tools such as [smtp_user_enum](https://www.kali.org/tools/smtp-user-enum/) 

## Exploiting
Once we've gathered the usernames and the type of SMTP server and OS running, we can advance to the exploitation face. For this we rely on other services to be open so we can try and bruteforce our way into the system, other exploits that we can take advantage of, or some really good OSINT. In case that the first one is true we can simply try a [[Hydra]] attack and hope that we can get the password.

# MySQL
Is a relational database management system (RDBMS) based on Structured query Language (SQL). MySQL is made up of the server and utility programs that help in the administration of MySQL databases.
The server handles all database instructions like creating, editing, and accessing data. It takes and manages these requests and communicates using the MySQL protocol. This process can be summarized into:
- MySQL creates a databese for storing and manipulating data, defining the relationship of each table
- Clients make requests by making specific statements in SQL
- The server will respond to the client with whatever information has been requested.
MySQL can run on various platforms, be it Linux or Windows. It is commonly used as a back end database for many prominent websites and forms an essential component of the LAMP stack (Linux, Apache, MySQL, PHP).
## Enumerating
MySQL is likely not going to be the first point of call when getting initial information about the server. We of course could try brute-forcing default account passwords if we don't have any other information but still it would be rare.
To connect to the remote MySQL server we are going to need the `default-mysql-client`, so we will be able to use the `mysql` command to connect to the server
```shell
mysql -h IP -u username -p
```
We can use [[Metasploit]] for enumeration as well with things like `mysql_version` or `mysql_enum`. But specially `mysql_sql` which allows us (provided with credentials) to run SQL commands like `show databases` among others. 
Some Metasploit-free alternatives can be [[Nmap]] `mysql-enum` script. Or running the commands inside the `mysql` server

# RDP
## Exploiting
Let's say that we found an exposed RDP service on it's default port. We can use a tool such as [RDPassSpray](https://github.com/xFreed0m/RDPassSpray) to [[Password Attacks#Password Spraying|password spray]] against RDP. 
```shell
python3 RDPassSpray.py -U usernames.txt -p Password2024! -t 10.10.10.10:3389
```
This follows the same guides like hydra, where an uppercase option refers to multiple names/passwords and a lowercase a single one.
We can also specify a domain name using `-d` if we are in an Active Directory environment.