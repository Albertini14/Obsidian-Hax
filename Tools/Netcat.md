Netcat is a command line application that has different uses. It supports both TCP and UDP protocols. It can function as a client that connects to a listening port; alternatively, it can act as a server that listens on a port of our choice.

To connect to a server:
```bash
nc IP PORT
```

We can then, in another terminal, open netcat in listening mode in order to echo whatever we type on one side to the other side of the TCP tunnel

```bash
nc -n -l -v -p PORT
nc -nlvp 9001 #same
```

|option|meaning|
|---|---|
|-l|Listen mode|
|-p|Specify the Port number|
|-n|Numeric only; no resolution of hostnames via DNS|
|-v|Verbose output (optional, yet useful to discover any bugs)|
|-vv|Very Verbose (optional)|
|-k|Keep listening after client disconnects|
|-e [Shell]|Executes a program for us to use with a reverse shell usually in /bin/[sh/zsh/shell]|
