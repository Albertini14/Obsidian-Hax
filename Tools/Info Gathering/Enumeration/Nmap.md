nmap IP - scans an IP

|Scan Type|Example Command|
|---|---|
|ARP Scan|`sudo nmap -PR -sn MACHINE_IP/24`|
|ICMP Echo Scan|`sudo nmap -PE -sn MACHINE_IP/24`|
|ICMP Timestamp Scan|`sudo nmap -PP -sn MACHINE_IP/24`|
|ICMP Address Mask Scan|`sudo nmap -PM -sn MACHINE_IP/24`|
|TCP SYN Ping Scan|`sudo nmap -PS22,80,443 -sn MACHINE_IP/30`|
|TCP ACK Ping Scan|`sudo nmap -PA22,80,443 -sn MACHINE_IP/30`|
|UDP Ping Scan|`sudo nmap -PU53,161,162 -sn MACHINE_IP/30`|

| Option | Purpose |
| ---- | ---- |
| `-n` | no DNS lookup |
| `-R` | reverse-DNS lookup for all hosts |
| `-sn` | host discovery only |
| `-Pn` | does not ping a host before scanning it |

| Port Scan Type                 | Example Command                                         |
| ------------------------------ | ------------------------------------------------------- |
| TCP Connect Scan               | `nmap -sT 10.10.105.22`                                 |
| TCP SYN Scan                   | `sudo nmap -sS 10.10.105.22`                            |
| UDP Scan                       | `sudo nmap -sU 10.10.105.22`                            |
| TCP Null Scan                  | `sudo nmap -sN 10.10.39.248`                            |
| TCP FIN Scan                   | `sudo nmap -sF 10.10.39.248`                            |
| TCP Xmas Scan                  | `sudo nmap -sX 10.10.39.248`                            |
| TCP Maimon Scan                | `sudo nmap -sM 10.10.39.248`                            |
| TCP ACK Scan                   | `sudo nmap -sA 10.10.39.248`                            |
| TCP Window Scan                | `sudo nmap -sW 10.10.39.248`                            |
| Custom TCP Scan                | `sudo nmap --scanflags URGACKPSHRSTSYNFIN 10.10.39.248` |
| Spoofed Source IP              | `sudo nmap -S SPOOFED_IP 10.10.39.248`                  |
| Spoofed MAC Address            | `--spoof-mac SPOOFED_MAC`                               |
| Decoy Scan                     | `nmap -D DECOY_IP,ME 10.10.39.248`                      |
| Idle (Zombie) Scan             | `sudo nmap -sI ZOMBIE_IP 10.10.39.248`                  |
| Fragment IP data into 8 bytes  | `-f`                                                    |
| Fragment IP data into 16 bytes | `-ff`                                                   |

|Option|Purpose|
|---|---|
|`-p-`|all ports|
|`-p1-1023`|scan ports 1 to 1023|
|`-F`|100 most common ports|
|`-r`|scan ports in consecutive order|
|`-T<0-5>`|-T0 being the slowest and T5 the fastest|
|`--max-rate 50`|rate <= 50 packets/sec|
|`--min-rate 15`|rate >= 15 packets/sec|
|`--min-parallelism 100`|at least 100 probes in parallel|
|`--source-port PORT_NUM`|specify source port number|
|`--data-length NUM`|append random data to reach given length|
|`--reason`|explains how Nmap made its conclusion|
|`-v`|verbose|
|`-vv`|very verbose|
|`-d`|debugging|
|`-dd`|more details for debugging|

| Option                      | Meaning                                         |
| --------------------------- | ----------------------------------------------- |
| `-sV`                       | determine service/version info on open ports    |
| `-sUV`                      | determine service/version on UDP ports          |
| `-sV --version-light`       | try the most likely probes (2)                  |
| `-sV --version-all`         | try all available probes (9)                    |
| `-O`                        | detect OS                                       |
| `--traceroute`              | run traceroute to target                        |
| `--script=SCRIPTS`          | Nmap scripts to run                             |
| `-sC` or `--script=default` | run default scripts                             |
| `-A`                        | equivalent to `-sV -O -sC --traceroute`         |
| `-oN`                       | save output in normal format                    |
| `-oG`                       | save output in grepable format                  |
| `-oX`                       | save output in XML format                       |
| `-oA`                       | save output in normal, XML and Grepable formats |
Aggresive bish
```sh
nmap IP -A -P- -oN version-scan
```

# Discover Live Hosts
## Enumerating Targets
Before going into the different techniques for scanning , there are different ways to specify the targets we want to scan such as
* List: `MachineIP DOMAIN.ORG EXAMPLE.COM` will scan all the IPs in the list
* Range: `*.*.*.MIN-MAX` which will scan all the IPs from the min to the maximum (`10.11.12.15-20` will scan 6 IPs)
	* Subnet: `MACHINEIP/BITS` will scan the remaining bits of IPs in the range that the given IP is from`10.11.12.5/30` will scan 4 IP addresses from 4 to 7)
* Provide file: `nmap -iL list.txt` 
We can always check the list of targets `nmap -sL TARGETS` this option will give us a detailed list of the hosts that Nmap will scan without scanning them. however, Nmap will attempt a reverse-DNS resolution on all targets to obtain their names. Names might reveal various information to the pentester (If no want DNS to server add `-n`)
## ARP scan
Is a scan that relays on the Address Resolution Protocol queries to discover live hosts. An ARP query aims to get the MAC address so that communication over the link-layer becomes possible, thanks to this we can use it to infer that the host is online. 
The ARP scan can only discover devices within a subnet **(\*.\*.\*.0/24)**, in case that we are not connected to the same subnet as our target all the packets generated by our scanner will be routed via the router to reach systems on another subnet, however, the ARP queries cannot cross the subnet router as it is a link-layer protocol and their packets are bound to their subnet.
If we want to run an Nmap with only an ARP scan without any port-scanning we can use `nmap -PR -sn TARGETS` where `-PR` indicates that we only want an ARP scan. We may add `sudo` for the scan to deliver more information sometimes.
## ICMP scan
We can ping every IP address on a target network and see who would respond to our ping (ICMP Type 8 /Echo) requests with a ping reply (ICMP Type 0). Although very simple not reliable as many firewalls block ICMP echo.
To use it to discover live hosts we use the option `-PE` to specify ICMP echo.
If ICMP echo requests are blocked we can also use ICMP Timestamp or ICMP Address Mask requests to tell if a system is online. 
Nmap uses Timestamp request (ICMP Type 13) and checks whether it will get a Timestamp reply (ICMP Type 14). Adding the `-PP` option tells Nmap to use ICMP timestamp requests. Similarly we can use `-PM` to send address mask queries (ICMP Type 17) and checks whether it gets and address mask reply (ICMP Type 18).
## TCP/UDP ping scan
### TCP SYN Ping
We can send a packet with the SYN flag set to a TCP port and wait for a response. An open port should reply with SYN/ACK and a closed one with RST. In this case we only check whether we will get any response to infer if the host is up. To do this TCP SYN ping we use `-PS` followed by the port number (default 80), range, list or combination of them (`-PS21-23` which will test the ports going from 21 to 23)
### TCP ACK Ping
This sends a packet with an ACK flag set, must be run by a privileged user, if not Nmap will attempt a 3-way handshake. We use `-PA` followed by a port similar to TCP SYN
### UDP Ping
We can also use UDP to discover if the host is online. Contrary to TCP SYN, sending a UDP packet to an open port is not expected to lead to any reply, however, if we send a UDP packet to a closed UDP port, we expect to get an ICMP port unreachable packet, thus, indicating that the target system is up.
The syntax of ports is similar of that of the previous methods and the option is `-PU` 


# Port scans
## TCP Connect Scan
By sending SYN packets to each port we can see how that port reacts, if we receive a SYN/ACK from a port then it represents that connections can be established and the port is open, then we can send an ACK and RST/ACK to end the connection. This is the procedure that a TCP Connect Scan follows, by trying to connect to each port and ending the connection we can know which ports are open. `-sT` indicates to use this type of scan, we can also use `-F` to enable fast mode and only scan the 100 most used ports and `-r` to test scan the ports in consecutive order, useful when testing if ports open in a consistent manner, ie, when a target boots up
## TCP SYN Scan
Unprivileged users are limited to connect scan. However, the default scan mode is SYN scan and it requires root to run it. SYN scan does not need to complete the TCP 3-way handshake, instead, it tears down the connection once it receives a response from the server. 
Thanks to the TCP connection not being established, this lowers our chances of the scan being logged. We can select this scan by using `-sS`
## UDP Scan
UDP is a connectionless protocol that does not requiere any handshake. Thus we cannot guarantee that a service listening on a UDP port is going to respond to our packets, however, if a UDP packet is sent to a closed port, an ICMP port unreachable error (type 3, code 3) is returned, allowing us to know which ports are closed, thus, also knowing which ones are open or filtered. We use this type of scan with `-sU`
## Null Scan
The null scan does not set any flag, all six flag bits are set to zero, we can use this with `-sN`. A TCP packet with no flags set will not trigger a response when it reaches an open port, therefore, from Nmap's perspective a lack of reply indicates that either the port is open or a firewall is blocking the packet, due to the fact that, if a port is closed it will respond with a RST/ACK packet. Needs root.
## FIN Scan
This scan sends a TCP packet with the FIN flag set `-sF`. Similarly to the null scan, no response will be sent if the TCP port is open or if there is a firewall blocking traffic related to this TCP port. And similarly a closed port will respond with RST/ACK
## Xmas Scan
Xmas Scan sets the FIN, PSH and URG flags simultaneously with `-sX`. Functioning the same as a FIN or Null scan, if a RST packet is received the port is closed, otherwise is either open or filtered
## Maimon Scan
In this type of scan both the FIN and ACK bits are set `-sM`. The target should send an RST packet as a response, however, certain BSD-derived (Berkeley Software Distribution) systems drop the packet if it is an open port exposing the open ports, resulting in not working in most modern networks as it doesn't matter if the port is closed or open it will send a RST packet regardless.
## ACK Scan
With `-sA` we can use a scan that only uses the ACK flag, the target would respond with RST regardless of the state of the port. This happens because a TCP packet with the ACK flag set should only be sent in response to a received TCP packet, hence, this scan won't tell us whether the target port is open in a simple setup. BUT, this scan is helpful against targets with firewalls, based on which ACK packets result in responses we can learn which ports were not blocked by firewalls
## Window Scan
The TCP window Scan `-sW` is very similar to the ACK scan, however, it examines the TCP window field of the RST packets returned. On specific systems, this can reveal that the port is open. Nmap would interpret the information of unfiltered ports as closed.
## Custom Scan
If we want to create our own combinations of TCP flags we can use `--scanflags` followed by the flags, like `--scanflags RSTSYNFIN`
## Spoofing IP
An attack that relies on spoofing an IP address to trick the target system into responding differently according to the spoofed IP `-S SPOOFED_IP TARGET_IP`, for this scan to work we need to use network traffic analysers to see the replies as they will be directed to the spoofed IP instead of ours. We also use `-e` to specify the network interface and `-Pn` to disable ping scan so it will end up like `nmap -e NET_INTERFACE -Pn -S SPOOFED TARGET`.
## Spoofing MAC
If we are in the same subnet as the target machine we can spoof the MAC address as well `--spoof-mac SPOOFED_MAC`, this only works if the attacker and target machine are on the same ethernet network or same WiFi
## Decoy Scan
We can also use spoofing to launch decoy attacks to make it harder for the blue team to pinpoint us with `nmap -D IP,IP,ME TARGET_IP` we can also use `RND` instead of an IP to generate one at random
## Fragmented Packets
With `-f` we can use the option to fragment packets, this way the IP data will be divided into 8 bytes or less, adding another (`-ff`) will split the data into 16 byte fragments. This way due to the packets being incomplete they may not check the rules predefined in firewalls and IDS to drop the packets, allowing us to complete the scan
## Idle/Zombie Scan
This scan requieres a zombie system connected to the network that we can communicate with, nmap then will spoof this zombie system and will check for indicators whether the zombie host received any response by checking the IP ID value in the IP header. `namp -sI ZOMBIE TARGET`
This scan requieres three thing in order to function:
* Trigger the zombie host to respond so that we can record the current IP ID on the zombie host
* Send a SYN packet to a TCP port on the target spoofed to appear as if it was coming from the zombie
* Trigger the zombie machine again to respond so that we can compare the new IP ID with the one we received earlier

We then can look at the difference in the IP IDs triggered between each scan, if the difference is 1 it indicates that either the port in the target machine is closed or there is a firewall that dropped the packet, if the difference is 2, then the target machine will send a SYN/ACK packet to the zombie host incrementing its IP ID by one, causing the total difference to be 2. 
This only works in idle hosts that are not busy at all (printers and stuff) if the host is busy the returned IP IDs will be worthless


# Service Detection
Once we have discovered the open ports we can probe those ports to detect the running services in each one. With the `-sV` option our nmap command will connect and determine service and versione information for the open ports. We can control the intensity with `--version-intensity LEVEL` where level ranges between 0-9, from lightest to the most complete.
Using service detection will force Nmap to proceed with the TCP 3-way handshake and establish connection in order to discover the version so a stealth SYN scan is not possible when this option is chosen. 
Unlike the service column the version column is not a guess based on the port opened. It is the real deal. 
requires root

# OS Detection
With Nmap we can also detect the OS running in the target IP with `-O`, it detects it based on its behaviour and any telltale signs in its responses. Although convenient many factors might affect its accuracy like virtualisation and similar technologies, so not to be taken as fax.

# Traceroute
To find the routers between us and the target we can use `--traceroute`, although similar not the same as the command `traceroute`on linux. The standard command starts with a packet of low TTL and keeps increasing it until it reaches the target, Nmap's traceroute starts with a packet of high TTL and keeps decreasing it.
Keep in mind that many routers are configured to not send ICMP TTL exceeded, which would prevent us from discovering their IP addresses

# NSE
Nmap Scripting Engine is a part of Nmap that allows a Lua interpreter to execute scripts. The default Nmap installation comes with hundreds of scripts that are named starting with the protocol they target. We can run the scripts in the default category using `--script=default`, or `-sC`. There are also another categories besides default.

|Script Category|Description|
|---|---|
|`auth`|Authentication related scripts|
|`broadcast`|Discover hosts by sending broadcast messages|
|`brute`|Performs brute-force password auditing against logins|
|`default`|Default scripts, same as `-sC`|
|`discovery`|Retrieve accessible information, such as database tables and DNS names|
|`dos`|Detects servers vulnerable to Denial of Service (DoS)|
|`exploit`|Attempts to exploit various vulnerable services|
|`external`|Checks using a third-party service, such as Geoplugin and Virustotal|
|`fuzzer`|Launch fuzzing attacks|
|`intrusive`|Brute-force attacks and exploitation, may damage target |
|`malware`|Scans for backdoors|
|`safe`|Safe scripts that won’t crash the target|
|`version`|Retrieve service versions|
|`vuln`|Checks for vulnerabilities or exploit vulnerable services|

with some scripts belonging to more than one category, some may be dangerous and can even crash services so be careful.
We can also specify the script by name using `--script "SCRIPT_NAME"` or a pattern such as `--script "ftp*"`, which would include every script starting with ftp

A full list of scripts and their corresponding arguments (along with example use cases) can be found [here](https://nmap.org/nsedoc/).

# Saving Output
Whenever we are running an Nmap scan, it is good practice to save the results in a file. There are 4 formats.
* Normal
* Grepable
* XML
* Script Kiddie (31337 H4x0r)
## Normal
The normal format, similar to the output that we get on the screen when scanning a target. `-oN FILENAME`
## Grepable
This format has its name from the command `grep`, standing for Global Regular Expression Printer, in simpler terms it makes filtering the scan output for specific keywords or terms efficient. `-oG FILENAME`. 
## XML
We can also save the results in XML format using `-oX FILENAME`, this would be the most convenient to process the output in other programs. 
## 5cR1P7 KiDD13
7H15 F0rM47 F0110W5 7H3 31337 5UP4 H4X0r 41PH4 M1ND537 4ND 17 C0U1D N07 83 M0r3 U531355 `-oS F1l3N4M3` 

# Evasion
Your typical Windows host will, with its default firewall, block all ICMP packets. This presents a problem: not only do we often use _ping_ to manually establish the activity of a target, Nmap does the same thing by default. This means that Nmap will register a host with this firewall configuration as dead and not bother scanning it at all.

So, we need a way to get around this configuration. Fortunately Nmap provides an option for this: `-Pn`, which tells Nmap to not bother pinging the host before scanning it. This means that Nmap will always treat the target host(s) as being alive, effectively bypassing the ICMP block; however, it comes at the price of potentially taking a very long time to complete the scan (if the host really is dead then Nmap will still be checking and double checking every specified port).

It's worth noting that if we've already directly on the local network, Nmap can also use ARP requests to determine host activity.

There are a variety of other switches which Nmap considers useful for firewall evasion. Refer to [here](https://nmap.org/book/man-bypass-firewalls-ids.html).

The following switches are of particular note:

- `-f`:- Used to fragment the packets (i.e. split them into smaller pieces) making it less likely that the packets will be detected by a firewall or IDS.
- An alternative to `-f`, but providing more control over the size of the packets: `--mtu <number>`, accepts a maximum transmission unit size to use for the packets sent. This _must_ be a multiple of 8.
- `--scan-delay <time>ms`:- used to add a delay between packets sent. This is very useful if the network is unstable, but also for evading any time-based firewall/IDS triggers which may be in place.
- `--badsum`:- this is used to generate in invalid checksum for packets. Any real TCP/IP stack would drop this packet, however, firewalls may potentially respond automatically, without bothering to check the checksum of the packet. As such, this switch can be used to determine the presence of a firewall/IDS.