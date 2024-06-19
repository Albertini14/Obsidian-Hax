## OSINT
### SSL/TLS Certificates
When a Secure Sockets Layer/Transport Layer Security is created for a domain by a Certificate Authority (CA) they take part in Certificate Transparency logs (CT). These are publicly accessible logs of every SSL/TLS certificate created for a domain name. The purpose of CT logs is to stop malicious and accidentally made certificates from being used.

We can use this to discover subdomains belonging to a domain, sites like [crt.sh](http://crt.sh/) and [ctsearch](https://ui.ctsearch.entrust.com/ui/ctsearchui) offer a database of certificates that show current and historical results

### Search Engines
Using advanced search methods on websites like Google such as site: and [[Content Discovery#Google Dorking |others]] can narrow the search results, for example 
	-site:www.domain.com site:\*.domain.com
Will show results leading to the domain excluding those with www 

### Sublist3r
To speed up the process of OSINT subdomain discovery there exists [[Sublist3r]] to automate the above methods

## Brute Force
### DNS Brute Force
Bruteforce Domain Name System enumeration tries many common subdomains with automation tools like
* [[dnsrecon]]

## Virtual Host
When subdomains are not hosted in publicly accessible DNS results, the DNS record could be kept no a private DNS server or recorded on the developer's machine in their /etc/hosts file which maps domain names to IP addresses.
Because web servers can host multiple websites from one server when a website is requested from a client, the server knows which website the client wants from the Host header. We can make changes to it and monitor the response to see if a new site comes up.

For this we can use [[ffuf]] 

thm wordilst:

	/usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt