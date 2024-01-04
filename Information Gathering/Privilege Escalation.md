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
