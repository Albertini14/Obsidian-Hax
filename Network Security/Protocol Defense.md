# TLS
The Transport Layer Security is a standard solution to protect both the confidentiality and integrity of exchanged packets, working against [[Protocol Attack#Sniffing Attack|Sniffing]] and [[Protocol Attack#MITM|MITM]] attacks.
TLS and SSL (Secure Sockets Layer, the precursor of TLS) work by encrypting adding an encryption to the protocols via the presentation layer, consequently making all the data passed through the transport and network layer encrypted.
An existing cleartext protocol can be upgraded to use Encryption via SSL/TLS like:

|Protocol|Default Port|Secured Protocol|Default Port with TLS|
|---|---|---|---|
|HTTP|80|HTTPS|443|
|FTP|21|FTPS|990|
|SMTP|25|SMTPS|465|
|POP3|110|POP3S|995|
|IMAP|143|IMAPS|993|

This method creates a Key for both the server and the client that will be securely generated so that any third party monitoring the channel wouldn't be able to discover it and thus decrypt the data.

# SSH
Secure Shell was created to provide a secure way for remote system administration as it lets us securely connect to another system over the network and execute commands on the remote system, SSH confirms the identity of the remote server, encrypts messages and both sides can detect any modification in the messages. SSH normally listens on port `22` and the client can authenticate using either a username and a password or a private and public key (after the SSH server is configured to recognise the corresponding public key).
We can connect to an SSH server using `ssh USER@IP`, if a server is listening on the default server it will ask to provide the password for the user, once authenticated, we will have access to the target server's terminal.
We can also use SSH to transfer files using SCP (Secure Copy Protocol) based on the SSH protocol with the following syntax `scp USER@IP:/home/file.txt ~` 
which will copy the file named *file.txt* to the root of our home directory (~). We can also copy files from out system to theirs by changing the order `scp ours.txt USER@IP:/home` 