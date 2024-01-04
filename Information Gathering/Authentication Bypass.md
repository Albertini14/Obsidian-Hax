### Username Enumeration
One helpful thing to have is a list of valid usernames that already exist in the server, we can find this usually in the signing up page due to the "no repetitive user names" error message.
By using the almighty [[ffuf]] we can do a POST request to the page, filling up the signup form, iterating through our list of usernames from a wordlist until we get an error and then we can add that username to a list.

THM wordlist
/usr/share/wordlists/SecLists/Usernames/Names/names.txt

### Brute Force
After finding out the usernames, we can iterate through them and also a list of passwords, until one of them works with, surprise, [[ffuf]]

THM passlist
/usr/share/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-100.txt

### Logic Flaw
In some cases logical flaws are the most important kind of flaws, for as they can be exploited without necesarly breaking in the system. For example, suposing that a certain webserver has a 

### Cooking cookies
Cookie tampering (or the cooler brother cooking cookies) is a way to exploit the existance of cookies in order to edit them and grant us access to more privilages.

You can cook cookies by either inspecting the page or by creating a request with curl, using the header "Cookie: variable=value".

Cookies can also be hashed so you may use  [crackstation](https://crackstation.net/) as a database to dehashed them. Or can also encode and decode the values in base32, base64 using [base64encode](https://www.base64encode.org/es/) 