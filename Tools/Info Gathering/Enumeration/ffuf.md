DESCRIPTION
[Github](https://github.com/ffuf/ffuf).


-u state the website ending with /FUZZ as a placeholder
-w takes a list of words to iterate through (wordlist.txt)

Find content in domain
```bash
ffuf -w WORDLIST -u URL/FUZZ
```

-w wordlist
-H switch adds/edits a header (like the Host header)
-u url to try
-fs filter out certain sizes

Find subdomains
```bash
ffuf -w WORDLIST -H "Host: FUZZ.DOMAIN.com" -u URL -fs {size}
```

-w wordlist
-X specifies the request method, in this case POST (normally GET)
-d data that we are going to send, by inspecting the textbar we can use the name of it to input the data
-H is used to add additional headers to the request. In this case we set the content type so the webserver knows we are sending form data
-u URL
-mr text on the page that we are looking for

Username Enumeration
```bash
ffuf -w WORDLIST -X POST -d "username=FUZZ&email=x&password=x&cpassword=x&TEXTBARNAME=DATA" -H "Content-Type: application/x-www-form-urlencoded" -u URL -mr "username already exists"
```

-w Wordlist, coma separated to indicate the two lists to iterate through
-X Post request
-d data to send and to iterate, substitute FUZZ with W1 and W2
-H indicate that we are sending a form data
-u URL
-fc filter by HTTP status code, normally by 200, as we do not want that

User/Password
```bash
ffuf -w USERLIST:W1,PASSLIST:W2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-www-form-urlencoded" -u URL -fc {HTTP status code}
```
