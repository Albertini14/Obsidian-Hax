# Phishing
## Infrastructure
### Domain Name
We'll need to register either an authentic-looking domain name or one that mimics the identity of another domain. Choosing the right Phishing domain to launch our attack from is essential to ensure we have the psychological edge over our target. We can use some of the following methods for choosing the perfect domain name.
#### Expired Domains
Although not essential, buying a domain name with some history may lead to better scoring of our domain when it comes to spam filters. Spam filters have a tendency to not trust brand new domain names compared to ones with some history.
#### Typosquatting
Typosquatting is when a registered domain looks very similar to the target domain we are trying to impersonate. Somo common methods are misspelling, adding an additional period, switching numbers for letters, phrasing, or an additional word.
#### TLD Alternatives
A Top Level Domain, is the .com .net .co .gov etc. part of a domain name, there are hundreds of variants of TLD's now. A common trick for choosing a domain would be to use the same name but with a different TLD
#### IDN Homograph Attack/Script Spoofing
Originally domain names were made up of Latin characters a-z and 0-9, but in 1998, IDN (internationalized domain name) was implemented to support language-specific script or alphabet from other languages such as Arabic, Chinese, Cyrillic, Hebrew and more. An issue that arises from the IDN implementation is that different letters from different languages can actually appear identical. For example, Unicode character U+0430 (Cyrillic small letter a) looks identical to Unicode character U+0061 (Latin small letter a), enabling attackers to register a domain that looks almost identical to another.
### SSL/TLS Certificates
Creating SSL/TLS certificates for our chosen domain will add an extra layer of authenticity to the attack
### Email Server/Account
Set up either an email server or register with an SMTP email provider
### DNS records
Setting up DNS Records such as SPF, DKIM, DMARC will improve the deliverability of our emails and make suer they are getting into the inbox rather than the spam folder.
### Web Server
We'll need to set up webservers or purchase web hosting from a company to host our phishing websites. Adding SSL/TLS to the websites will give them an extra layer of authenticity.
### Analytics
When a phishing campaign is ongoing, keeping analytics information is crucial. We need to keep track of the emails that have been sent, opened, or clicked. We also need to combine it with information from our phishing websites that may have gathered user PI or from which they download software.
## Automation
There are some frameworks which automate some of the features from the infrastructure section
### [[GoPhish]]
GoPhish is a web-based Open-Source Phishing framework to make setting up phishing campaigns more straightforward. GoPhish allows us to store our SMTP server settings for sending emails, and it has a web-based tool for creating email templates using a simple WYSIWYG (What You See Is What You Get) editor. We can also schedule when emails are sent and have analytics dashboard that shows how many emails have been sent, open or clicked.
### [SET](https://www.trustedsec.com/tools/the-social-engineer-toolkit-set/)
The Social Engineering Toolkit contains a multitude of tools, some more important for phishing are the ability to create spear-phishing attacks and deploy fake versions of common websites to trick victims into entering their credentials
## Droppers
Droppers are software that phishing victims tend to be tricked into downloading and running and on their system. The dropper may advertise itself as something useful or legitimate such as a codec to view a certain video or software to open a specific file.
The droppers are not usually malicious themselves, so they tend to pass antivirus checks. Once installed, the intended malware is either unpacked or downloaded from a server and installed onto the victim's computer. The malicious software usually connects back to the attacker's infrastructure. The attacker can take control of the victim's computer, which can further explore and exploit the local network.
### MS Office
Often during phishing campaigns, a Microsoft Office Document, will be included as an attachment. Office documents can contain [[Payload Delivery#VBA|macros]], that can allow us to install malware onto the victim's computer or connect back to an attacker's network.
