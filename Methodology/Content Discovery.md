## Manual discovery
### /robots.txt
URL/robots.txt
path for a url that states which directories are allowed and not allowed 

### Favicon
![[Pasted image 20231023154000.png]]
A favicon is the little icon in the left of the tab, when creating a page with a framework, if not changed by the developer, they may leave those icons so we can retrieve them and compare them to a library to figure out which framework was used

[OWASP Favicon database](https://wiki.owasp.org/index.php/OWASP_favicon_database)
```bash
curl URL/favicon.ico | md5sum
```

we can use this command to get the favicon icon and then pipe it through md5sum to get the hash so that can be later used to find the framework in the database

### /sitemap.xml
Similar to robots.txt, the sitemap.xml is a type of file that shows the priority in which certain paths for sites will be showed when queried by the search engine. DOES NOT WORK ON EVERY SITE

### HTTP Headers
When making requests web servers, the server return various HTTP headers which can contain information about the web server software and the language in use

```bash
curl URL -v
``` 



## OSINT
### Google Dorking

Google dorking utilises google's advanced search engine features to pick out custom content. you can combine multiple filters

| Filter     | Example            | Description                                                                             |
| ---------- | ------------------ | --------------------------------------------------------------------------------------- |
| `exact`    | "search phrase"    | Find results with exact search phrase                                                   |
| `site`     | site:tryhackme.com | returns results only from the specified website address (can use -site to exclude from) |
| `inurl`    | inurl:admin        | returns results that have the specified word in the URL                                 |
| `filetype` | filetype:pdf       | returns results which are a particular file extension                                   |
| `intitle`  | intitle:admin      | returns results that contain the specified word in the title                            |
### Wappalyzer
Is an online tool and browser extension that helps identify what technologies a website uses, such as frameworks, content management systems (CMS), payment processors and much more
[Wappalyzer](https://www.wappalyzer.com/)

### Wayback Machine
Is a historical archive of websites that dates back to the late 90s. It will show all the times the service scraped the web page and saved the contents. This service can help uncover old pages that may still be active on the current website
[Time machine](https://archive.org/web/)

### GitHub
You can use GitHub's search feature to look for company names or website names to try and locate repositories belonging to the target, and even have access to source code, passwords or other content.

### S3 Buckets
S3 buckets are a storage service provided by amazon AWS, allowing people to save files and even static website content in the cloud. The owner can set access permissions but if incorrectly set you can have access to files that shouldn't be available.

	 http(s)://{name}.s3.amazonaws.com

S3 buckets can be discovered through finding them in the website's page source, GitHub, or by automation by following the {name} with common terms such as -assets, -www, -public, -private, etc

## Automated Discovery
Process of using tools to discover content by the lazy method (Not doing shit).

[Curated wordlists](https://github.com/danielmiessler/SecLists)

We can use many different discovery tools, like

[[ffuf]]
[[dirb]]
[[GoBuster]]
