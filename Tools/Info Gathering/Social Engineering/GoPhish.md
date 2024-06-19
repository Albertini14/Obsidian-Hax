[GoPhish](https://getgophish.com/) 
## Sending Profiles
Sending profiles are the connection details required to actually send our phishing emails, this is just simply an SMTP server that we have access to. In here we can create a new profile from where we can set up the name, address and host of our profile like
```
Name:
Local server
From:
noreply@redteam.ctf
Host:
127.0.0.1:25
```

## Landing Pages
Next we can set up the landing page, this is the website that the phishing email is going to direct the victim to. This page is usually a spoof of a website the victim is familiar with.
We can give the landing page a name as well as enter the HTML of the page we want to spoof or even import one with the `import` button.
Also we can set the "Capture Submitted Data" box and then also the "capture passwords" box. After a user enters his credentials we can redirect them to other page.

## Email Templates
This is the design and content of the email we are going to actually send to the victim. Of course, it will need to be persuasive and contain a link to our landing page. Here we can either import the source of an email or create our own. If crafting our own it is important to note that we need to set the anchor texts link to `{{.URL}}` as this will redirect them to our landing page, we also need to select `<other>` as the protocol

## Users & Groups
This is where we can store the email addresses of our intended targets. 

## Campaigns
Once we have established all of the above, we can start a new campaign. Here we will need to set which template, landing page and targets that we set before want to use. We also need to specify a URL which GoPhish will use a listener. As well as the launch date, end date (if any, to distribute the emails evenly through this two dates) and the sending profile.

## Dashboard
Finally we can go to dashboard to see how our campaign is performing