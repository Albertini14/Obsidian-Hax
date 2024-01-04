The Telnet protocol is an application layer protocol used to connect to a virtual terminal of another computer. Using it, a user can log into another computer and access its terminal to run programs, start batch processes, and perform system administration tasks remotely

When a user connects with the Telnet protocol, they will be asked for a username and password. Upon correct authentication, the user will access the remote system's terminal. Unfortunately, all this communication between the Telnet client and the Telnet server is not encrypted, making it an easy target for attackers.

A Telnet server uses the Telnet protocol to listen for incoming connections on port `23`.

It's main command follows this syntax
`telnet IP PORT`