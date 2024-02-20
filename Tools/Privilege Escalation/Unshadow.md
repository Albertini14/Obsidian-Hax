#Linux #Outside
If we get a hod of both the `/etc/shadow` and `/etc/passwd` we can then use the command `unshadow` to create a file crackable by [[John The Ripper]]. To do this we just need the following
```sh
unshadow passwd shadow > passwords.txt
```
And then to crack it using [[John The Ripper]]
```sh
john passwords.txt
```
