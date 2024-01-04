Tool to scan the subdomains of a domain from a wordlist

-d | Domain name to scan
-D | dictionary to bruteforce hostnames
-t | type of scan to do (std, brt, etc.)
--xml | save as a xml file

```bash
dnsrecon -d example.com -D /usr/share/wordlists/dnsmap.txt -t std --xml dnsrecon.xml
```

