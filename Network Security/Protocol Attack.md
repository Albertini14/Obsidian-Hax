# Sniffing Attack
Sniffing attack refers to using a network packet capture tool to collect information about the target, whenever a protocol communicates in cleartext, the data exchanged can be captured by a third party to analyse and reveal information, such as the content of private messages and login credentials.
Sniffing can be conducted using an Ethernet (802.3) network card, provided that the user has proper permissions (root or admin), some programs that cana do this are:
* [[Tcpdump]]: Is a free open source CLI (command-line interface) program that has been ported to work on many OS
* [[Wireshark]]: is a free open source GUI program available for several OS like Linux, macOS and MS Windows
* [[Tshark]]: is a CLI alternative to Wireshark

The only thing this attack requieres is for us to have access to a system between the two communicating systems. The mitigation lies in adding an encryption layer on top of any network protocol like TLS or SSH for remote access.
# MITM
A Man-in-the-Middle attack occurs when a victim believes that they are communicating with a legitimate destination but is unknowingly communicating with an attacker who redirects the data to the original destination either with changes or not.
This attack is simple to carry out if the two parties do not confirm the authenticity and integrity of each message. Some protocols have inherent insecurities that make them susceptible to this kind of attack like HTTP (with tools like [[Ettercap]] and [[Bettercap]]).

MITM can also affect other cleartext protocols such as FTP, SMTP and POP3. Mitigation against this attack requires the use of cryptography, while the solution lies in proper authentication along with encryption or signing of the exchanged messages. With the use of Public Key Infrastructure (PKI) and trusted root certificates, TLS can protect from MITM attacks.

# Password attack
One way to automate password dictionary attacks is [[Hydra]] as it supports a shit ton of protocols. The general syntax is `hydra -l USER -P WORDLIST SERVER SERVICE` in which we specify the options as:
`-l USER` User, login name, etc.
`-P LIST`wordlist, text file
`SERVER` is the hostname or IP address
`SERVICE` indicates the service which we are trying to launch the dictionary attack (ftp, http, ssh, etc.)
`-s PORT` used to specify a non-default port
`-V` or `-vV` for verbose
`-t n` where n is the number of parallel connections to the target
`-d` for debugging, to get more detailed information, like if Hydra tries to connect to a closed port and times out.
