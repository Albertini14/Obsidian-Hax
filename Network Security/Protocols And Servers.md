| Protocol | TCP Port | Application(s) | Data Security |
| -------- | -------- | -------------- | ------------- |
| FTP      | 21       | File Transfer  | Cleartext     |
| HTTP     | 80       | Worldwide Web  | Cleartext     |
| IMAP     | 143      | Email (MDA)    | Cleartext     |
| POP3     | 110      | Email (MDA)    | Cleartext     |
| SMTP     | 25       | Email (MTA)    | Cleartext     |
| Telnet   | 23       | Remote Access  | Cleartext     |


# [[Telnet]]

## HTTP
Hypertetxt Transfer Protocol is the protocol used to transfer web pages. Our web browser connects to the webserver and uses HTTP to request HTML pages and images among other files and submit forms and upload various files. 

HTTP sends and receives data as clear text; therefore, we can use simple tools such as [[Telnet]] or [[Netcat]] to communicate with a web server and act as a "web browser". The difference being that we need to input the HTTP-related commands instead of the web browser doing it for us.

In order to request a page from a web server we can do it via Telnet by
* Connecting to the port `80` , used by default, like `telnet IP 80`
* Next, type what we want to retrieve, like `GET /index.html HTTP/1.1`
* And finally providing some value for the host like `host: telnet` 

## FTP
The File Transfer Protocol (FTP) was developed to make the transfer of files between different computers with different systems efficient. It also sends and receives data as clear text, thus, we can use [[Telnet]] to communicate with an FTP server and act as an FTP client. We can do this by:
* Connecting to the port `21`, used by default, like `telnet IP 21`
* Then provide a username `USER admin`
* And the password `PASS pas5word`

`STAT` can provide some added information. 
`SYST` command shows the System Type of the target. 
`PASV` switches the mode to passive. It is worth nothing that there are two modes for FTP:
* Active: The data is sent over a separate channel originating from the FTP server's port 20
* Passive: The data is sent over a separate channel originating from an FTP client's port above port number 1023
`TYPE A` switches the file transfer mode to ASCII.
`TYPE I` switches the file transfer mode to binary.
`QUIT` ends connection

We cannot transfer a file using a simple client such as Telnet due to the fact that FTP creates a separate connection for file transfer. 
Considering this we can use an FTP client to download a file. By using `ftp IP` we can then log in, once we are done with that a FTP prompt `ftp>` will appear allowing us to execute various FTP commands

`ls` lists the files
`ascii` switches to ASCII mode
`get FILE` establishes connection between client and server in another channel for file transfer
`exit` exits


## SMTP
Email delivery over the internet requires the following components:
* Mail Submission Agent (MSA): Receives a sent message by the MUA, checks it for any errors before transferring it to the MTA hosted on the same server
* Mail Transfer Agent (MTA): Will send the email message to the MTA of the recipient. For it to then send it to the MDA 
* Mail Delivery Agent (MDA): Delivers the email it to the MUA, which in a typical setup would have the MTA server also functioning as a MDA
* Mail User Agent (MUA): or simply an email client, it either has an email message to be sent or one that it will receive

We need to follow a protocol to communicate with an HTTP server, and we need to relay on email protocols to talk with an MTA and an MDA. Here three protocol come into place:
* Simple Mail Transfer Protocol
* POP3
* IMAP

SMTP is used to communicate with an MTA server. Because SMTP uses cleartext, we can use the [[Telnet]] client to connect to an SMTP server and act as an email client (MUA) sending a message.

* Connecting to Port `25`, used by default, like `telnet IP 25`
* Then issue `helo HOSTNAME`
* Sender `mail from: ADDRESS
* Recipient `rcpt to: ADDRESS`
* Issue `data` and then type out the message

## POP3
While SMTP is used to send email messages, Post Office Protocol version 3 is a protocol used to download the email messages from a MDA server. The mail client connects to the POP3 server, authenticates, downloads the new email message before (optionally) deleting them. 
Similarly to the others, as POP3 does not uses encryption we can use telnet by:
* Connecting to port `110`, used by default, like `telnet IP 110`
* Authenticates with `USER admin` and `PASS pas5word`

`STAT` we get a reply `+OK nn mm` where **nn** is the number of email messages in the inbox and **mm** is the size of the inbox in octets (byte)
`LIST` provides a list of new messages on the server
`RETR n` retrieves the n message in the list.

## IMAP
Internet Message Access Protocol is more sophisticated than POP3, as it makes possible to keep your email synchronised across multiple devices. As it it also sends data in clear text we can use [[Telnet]] 
- Connect to the port `143`, used by default, like `telnet IP 143`
- Authenticate with `LOGIN username password`
- IMAP requires each command to be preceded by a random string to be able to track the reply so the commands would end up looking like `c1 LOGIN...`, `c2 LIST...`

`LIST "" "*"` lists our mail folders
`EXAMINE INBOX` checks if we have any messages in the inbox

