# What is
A software or hardware that monitors the network traffic and compares it against a set of rules before passing or blocking it. Before starting it is helpful to remember the contents of an IP packet and TCP segment. Different types of firewalls are capable of inspecting various packet fields, however, the most basic firewall should be able to inspect at least the following:
- Protocol
- Source Address
- Destination Address
![[Pasted image 20241002171002.png]]
Depending on the protocol field, the data in the IP datagram can be one of many options. Three common protocol are:
- TCP
- UDP
- ICMP
In the case of TCP or UDP, the firewall should at least be able to check the TCP and UDP headers for:
- Source Port Number
- Destination Port Number
Below we can notice that there are many fields that the firewall might or might not be able to analyze.
![[Pasted image 20241002171923.png]]

## Type of Firewalls
There are multiple ways to classify firewalls. One way would be whether they are independent appliances.
1. Hardware Firewall (appliance firewall): As the name implies, an appliance firewall is a separate piece of hardware that the network traffic has to go through. Some examples include Cisco ASA (Adaptive Security Appliance), WatchGuard Firebox, and Netgate pfSense Plus appliance.
2. Software Firewall: A piece of software that comes bundled with the OS, or that we can install it as an additional service. MS Windows has a built-in firewall, Windows Defender Firewall, that runs along with other OS services and user applications. Another example is Linux iptables and firewalld.
We can also classify firewalls into:
1. Personal Firewall: A personal firewall is designed to protect a single system or a small network. Many wireless access points designed for homes have built-in firewall. One example is Bitdefender BOX. Another is the firewall that comes as part of many wireless access points and home routers from Linksys and Dlink.
2. Commercial Firewall: A commercial firewall protects medium-to-large networks. With a lot more reliability and processing power, in addition to a higher network bandwidth. 

---


From our perspective, the most crucial classification would be based on the firewall inspection abilities. It is worth thinking about the firewall abilities in terms of the OSI layers. Before classifying, it is worth noting that firewalls focus on **layers 3 and 4**, and to a lesser extent, **layer 2**. NGFW are also designed to cover **layers 5,6, and 7**. The more layers a firewall can inspect, the more sophisticated it gets and the more processing power it needs.
![[Pasted image 20241002181201.png]]
Based on firewall abilities, we can list the following firewall types:
- Packet-Filtering Firewall: Packet-filtering is the most basic type of firewall. This type of firewall inspects the protocol, source and destination IP addresses, and source and destination ports in the case of TCP and UDP datagrams. It is a stateless inspection Firewall.
- Circuit-Level Gateway: In addition to the features offered by the packet-filtering firewalls, circuit-level gateways can provide additional capabilities, such as checking TCP three-way-handshake against the firewall rules.
- Stateful Inspection Firewall: Compared to the previous types, this type of firewall gives an additional layer of protection as it keeps track of the established TCP sessions. As a result, it can detect and block any TCP packet outside an established TCP session.
- Proxy Firewall: A proxy firewall is also referred to as Application Firewall (AF) and Web Application Firewall (WAF). It is designed to masquerade as the original client and requests on its behalf. This process allows the proxy firewall to inspect the contents of the packet payload instead of being limited to the packet headers. Generally speaking, this is used for web applications and does not work for all protocols.
- NGFW: Next Gen Firewalls offer the highest protection. They can practically monitor all layers, from 2 to 7. It has application awareness and control. Some examples are, Juniper SRX series and Cisco Firepower.
- Cloud Firewall or Firewall as a Service (FWaaS): FWaaS replaces a hardware firewall in a cloud environment. Its features might be comparable to a NGFW, depending on the service provider, however, it benefits from the scalability of cloud architecture. One example is Cloudflare Magic firewall, which is a network-level firewall. Another examples is Juniper vSRX. It is also worth mentioning AWS WAF for web application protection and AWS Shield for DDoS protection.

# Controlling the Source MAC/IP/Port
When scanning a host behind a firewall, the firewall will usually detect and block port scans. This situation would require us to adapt our network and port scan to evade the Firewall. A network scanner like [[Nmap]] provides a few features to help with such tasks. We can group Nmap Techniques into three groups:
- Evasion via Controlling the source MAC/IP/Port
- Evasion via fragmentation, MTU, and data length
- Evasion through modifying header fields

Nmap allows us to hide or spoof the source as we can use:

| Evasion Approach                              | Nmap Argument                     |
| --------------------------------------------- | --------------------------------- |
| Hide a scan with decoys                       | `-D DECOY1_IP1,DECOY_IP2,ME`      |
| Hide a scan with random decoys                | `-D RND,RND,ME`                   |
| Use an HTTP/SOCKS4 proxy to relay connections | `--proxies PROXYUrl`              |
| Spoof source MAC address                      | `--spoof-mac SpoofedMAC`          |
| Spoof source IP address                       | `-S SpoofedIP`                    |
| Use a specific source port number             | `-g PORT` or `--source-port PORT` |
Before elaborating on each one. Let's look at a simple SYN scan. Made with the following command `namp -sS -Pn -F IP` we used [[Wireshark]] on the same system running Nmap.
![[Pasted image 20241002193325.png]]
Now, the things to note within these packet are:
- We sent around 200 packets, even though the `-F` flag only scans the 100 most common, it sends a second SYN packet if it does not reply to the first one.
- The source port number is chosen at random, in this case it took `37710`
- The total length of the packet is 44 bytes. There are 20 bytes for the IP header, leaving the other 24 for the TCP header. No data is sent via TCP
- The TTL is 42
- No errors are introduces in the checksum

## Decoy(s)
Hide our scan with decoys. Using decoys makes our IP address mix with other "decoy" IP addresses. Consequently it will be difficult for the firewall and the target host to know where the port scan is coming from. Furthermore, this can exhaust the blue team investigating each source IP address.
Using the `-D` option, we can add decoy source IP addresses to bamboozle our target. With just a comma delimited option like the following
```sh
nmap -sS -Pn -D 10.10.10.1,10.10.10.2,ME -F TargetIP
```
We will create multiple scans, each with a source IP address of the entered IPs. Note that if we omit the `ME` entry, nmap will put our IP address and then shuffle the order. Otherwise it will test following the order in which we entered them.
We can also set Nmap to use random source IP addresses with `RND`, instead of the IP. Note that these to look very random, so if we have something like 10.0.1.1 as our IP, we might stand out, due to looking very normal.

## Proxy
Using an HTTP/SOCKS4 proxy. Relaying the port scan via a proxy helps keep our IP addresses unknown to the target host. This technique allows us to keep our IP hidden while the target logs the IP address of the proxy server. We can do this with the `--proxies ProxyUrl`
```sh
nmap -sS -Pn --proxies ProxyUrl -F IP
```

## Spoofed MAC address
Nmap allows us to spoof our MAC address using `--spoof-mac MACAddress`. Spoofing the MAC address **only works if our system is on the same network segment as the target** host. Because the target system is going to reply to a spoofed MAC address, if we are not on the same network segment, sharing the same Ethernet, we won't be able to capture and read the responses. It allows us to exploit any trust relationship based on MAC addresses. Moreover, we can use this technique to hide our scanning activities on the network. For example, we could make our scans appear as if they were coming from the printer.

## Spoofed IP address
We can do this by using `-S SpoofedAddress`. Doing this is useful if our system is on the same subnetwork as the target host, otherwise we won't be able to read the replies sent back. Another use, is when we control the system that has that particular IP address, consequently if we notice that the target blocked our spoofed IP address, we could switch to a different spoofed address that belongs to a system that we control. Although this helps us with our stealth run, we could also use it to abuse trust relationships based on IP. 

## Fixed Source Port Number
Scanning from one particular source port number can be helpful if we discover that the firewall allows incoming packets from particular source port numbers, such as 53, 80 or 443. Without inspecting the packet contents, packets from source TP port 80 or 443, look like packets from a web server, while packets from UDP port 53 look like responses to DNS queries. We can set our source port number using `-g` or `--source-port` options.


# Forcing Fragmentation, MTU, and Data Length
We can control the packet size as it allows us to:
- Fragment packets, optionally with given MTU. If the firewall, or the [[Network Security Solutions#IDS Engine Types|IDS/IPS]], does not reassemble the packet, it will most likely let it pass. Consequently, the target system will reassemble and process it.
- Send packets with specific data lengths

| Evasion Approach                | Nmap Argument       |
| ------------------------------- | ------------------- |
| Fragment IP data into 8 bytes   | `-f`                |
| Fragment IP data into 16 bytes  | `-ff`               |
| Fragment packets with given MTU | `--mtu VALUE`       |
| Specify packet length           | `--data-length NUM` |
## Fragment Packets with 8/16 Bytes of Data
One easy way to fragment our packets would be to use the `-f` option. Fragmenting the IP packet to carry only 8 bytes of data. As mentioned before, in a normal TCP port scan the IP packet will hold 24 bytes, the TCP header. If we want to limit the IP data to 8 bytes, the 24 bytes of the TCP header will be divided across 3 IP packets.
To fragment it into 16 bytes, we just use `-ff` instead.
![[Pasted image 20241002221304.png]]
## Fragment According to a set MTU
Another way to fragment our packets is by setting the Maximum Transmission Unit (MTU). In Nmap, `--mtu VALUE` specifies the number of bytes per IP packet. (IP header not included). It must always be a multiple of 8.

## Generate Packets with Specific Length
In some instances, we might find out that the size of packets is triggering the firewall or the IDS/IPS to detect and block us. If in this situation, we can make our port scanning more evasive by setting a specific length. We can set the length of data carried within the IP packet using `--data-length VALUE`. Again multiple of 8.
When doing this, each TCP segment will be padded with random data till its length is that number of bytes.

# Modifying Header Fields
Nmap allows us to control various header fields that might help evade the firewall. For example we could:
- Set the IP TTL
- Send packets with specified IP options
- Send packets with a wrong TCP/UDP checksum

| Evasion Approach                           | Nmap Argument          |
| ------------------------------------------ | ---------------------- |
| Set IP time-to-live field                  | `--ttl VALUE`          |
| Send packets with specified IP options     | `--ip-options OPTIONS` |
| Send packets with a wrong TCP/UDP checksum | `--badsum`             |
## Set TTL
One of the fields we can control is the TTL. With the option `--ttl VALUE`, we can set a custom TTL. This might be useful if we think the default TTL exposes our port scan activities.

## Set IP Options
Nmap lets us control the value set in the IP options field using `--ip-options HEX_STRING`, where the hex string can specify the bytes we want to use to fill in the IP Options field. Each byte is written as `\xFF`, where `FF` represents a byte.
We can use a shortcut to make our requests:
- `R` to record-route.
- `T` to record-timestamp.
- `U` to record-route and record-timestamp.
- `L` for loose source routing and needs to be followed by a list of IP addresses separated by space.
- `S` for strict source routing and needs to be followed by a list of IP addresses separated by space.
To use this, we just need to pass them as an argument instead of the Hex string.

## Wrong Checksum
Some systems would drop a packet with a bad checksum, while other's won't. We can use this to our advantage to discover more about the system in our network. All we need to do is add the option `--badsum` to our Nmap command.

# Port Hopping
A technique where an application hops from port to port until it can establish and maintain a connection. So it may try different ports until it establishes a connection. Some "legitimate" applications use this technique to evade firewalls. 
There is another type of port hopping where the application establishes the connection on one port and starts transmitting some data, after a while, it establishes a new connection on a different port and resumes sending more data. The purpose is to make it more difficult for the blue team to detect and track all the exchanged traffic.

# Port Tunneling
Also known as port forwarding and port mapping. This technique forwards the packets sent to one destination port to another destination port. For example, packets sent to port 80 on one system are forwarded to port 8080 on another system.
## Using [[Netcat|Ncat]]
Suppose that we want to sent packets to the port 25 hosting an SMTP server, but packets to port 25 from the internet are blocked, however those to port 443 are not. We can send the packets to port 443 and then forward them to port 25 once they pass the firewall. From within the target system we can run the following command
```sh
ncat -lnvp 443 -c "ncat TargetServer 25"
```
With this we will be listening on port 443 (with root because it is under 1024), and execute (`-c`) our command that will connect to the target server at port 25 (`"ncat TargetServer 25"`)
## Other tools
- [[Chisel]]
- [[Ligolo-ng]] 

# NGFW
Traditional firewalls, such as packet-filtering firewalls, expect a port number to dictate the protocol being used and identify the application. Consequently if we want to block an application, we need to block a port. Now, a lot of applications camouflage themselves using ports assigned for other applications, so that is no longer reliable to identify the application being used.
NGFW is designed to handle the new challenges facing modern enterprises like:
- Integrate a firewall and a real-time Intrusion Prevention System (IPS). It can stop any detected threat in real-time.
- Identify users and their traffic. It can enforce the security policy per-user or per-group basis.
- Identify the applications and protocols regardless of the port number being used.
- Identify the content being transmitted. It can enforce the security policy in case any violating content is detected.
- Ability to decrypt SSL/TLS and SSH traffic. For instance, it restricts evasive techniques built around encryption to transfer malicious files.