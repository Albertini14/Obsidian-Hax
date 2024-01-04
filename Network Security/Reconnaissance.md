# Pasive Reconnaissance
## Whois
A command for linux that can be used to retrieve information about a domain, including the registrar, registrant, creation and expiration date of the domain, as well as information about certain people like the admin, tech team, etc.

## nslookup/dig
Both commands to gather information about the IP adresses of a domain server, we can query from different DNS servers like 1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 and many more, likewise we can use different types in order to get specific results from our query.

|Query type|Result                                     |
|-------------------|-|
|A|IPv4 Addresses|
|AAAA|IPv6 Addresses|
|CNAME|Canonical Name|
|MX|Mail Servers|
|SOA|Start of Authority|
|TXT|TXT Records|

```bash
nslookup -type=TYPE DOMAIN SERVER
dig @SERVER DOMAIN TYPE
```

## DNSDumpster

[DNSDumpster](https://dnsdumpster.com) is an online service that offers detailed answers to a DNS query, allowing us to find subdomains, TXT and MX records, IP servers, etc.

## Shodan.io
[Shodan.io](https://shodan.io) is an online service which tries to connect to every device reachable online to build a search engine of connected things rather than a web search engine, it collects all the information related to the service, thanks to this we can learn several things about our domain, like IP address, hosting company, geographical information, server type, connection, etc

# Active Reconnaissance
## Traceroute
Is a command that traces the route taken by the packets from our system to another host. It's purpose is to find the IP addresses of the routers or hops that a packet traverses as it goes from our system to the host.

## [[Telnet]]
Is a command that uses the Teletype Network protocol for remote administration, it sends all data, including usernames and passwords, in cleartext. Making it easy for anyone who has access to the communication channel to steal login credentials. It's secure alternative is SSH.

Beyond this it can be used for other purposes such as, if we know that a target relies on the TCP protocol, then we can use telnet to connect to any service and grab its banner. Using `telnet IP PORT` we can connect to any service running on TCP and exchange a few messages.

## [[Netcat]]
