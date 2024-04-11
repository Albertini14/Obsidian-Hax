Here we expand upon techniques in both [[Content Discovery]] and [[Reconnaissance]] 
# Passive 
## Built-in tools
Found on both Unix and Windows
### [[Reconnaissance#whois|whois]]
### [[Reconnaissance#nslookup/dig|nslookup/dig]]
### host
Another alternative for querying DNS servers for DNS records
```shell
host cafe.redteam.com
```
### [[Reconnaissance#Traceroute|traceroute]]
## [[Content Discovery#Google Dorking|Dorking]]
We can also refer to [Database](https://www.exploit-db.com/google-hacking-database) that collects combinations of advanced searching with specific terms.
## Specialized Search Engines
Beyond the standard WHOIS and DNS query tools, there are third parties that offer historical WHOIS data. So if the domain registrant didn't use privacy at first but then changed it we can see.
- [whois history](https://whois-history.whoisxmlapi.com/lookup)
- [whoxy](https://www.whoxy.com/whois-history/)
Something similar goes for advanced DNS services. Some of these are
- [ViewDNS.info](https://viewdns.info/)
- [Threat Intelligence Platform](https://threatintelligenceplatform.com/)
- [Censys](https://search.censys.io/) 
- [Shodan](https://www.shodan.io/)
## Automated
### Recon-ng
[[Recon-ng]] is a framework that helps automate OSINT work. Some modules require keys to work, these keys allow the module to query the related online API.
### Maltego
[Maltego](https://www.maltego.com/) is a web application that blends mind-mapping with OSINT. Generally we would start with a domain name, company name, person's name, email, etc. Then we let this piece of information go through various "Transforms" (each transform is a piece of code that would query an API to retrieve information related to a entity).
![[Pasted image 20240411051838.png]]
Some of the transforms might connect to the target system, so it's always better to know how they work first.