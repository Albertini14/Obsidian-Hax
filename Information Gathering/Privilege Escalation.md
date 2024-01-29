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