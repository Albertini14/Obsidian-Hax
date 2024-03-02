# Types Of Encryption
## Symmetric Encryption
Uses the same key to encrypt and decrypt the data. Examples of Symmetric encryption are DES (not secure anymore) and AES. These algorithms tend to be faster than asymmetric cryptography, and use smaller keys (128 or 256 bit keys are common for AES, DES keys are 56 bits long)
## Asymmetric Encryption
Uses a pair of keys, one to encrypt and the other to decrypt. Examples are RSA and Elliptic Curve Cryptography. Normally these keys are referred to as a public key and a private key. Data encrypted with the private key can be decrypted with the public key, and vice versa.
Asymmetric encryption tends to be slower and uses larger keys, for example RSA typically uses 2048 to 4096 bit keys. 
RSA and Elliptic Curve cryptography are based around different mathematically difficult (intractable) problems, which give them their strength.

A very common use of asymmetric cryptography is exchanging keys for symmetric encryption. Asymmetric encryption tends to be slower, so for things like HTTPS symmetric encryption is better. So they tend to transfer the key for the Symmetric encryption through Asymmetric encryption first and then continue the transfer symmetrically.

### RSA
Rivest Shamir Adleman (RSA) is based on the mathematically difficult problem of working out the factors of a large number. 
There are some excellent tools for defeating RSA challenges in CTFs, like [RSACTFTool](https://github.com/RsaCtfTool/RsaCtfTool) and [RSAtool](https://github.com/ius/rsatool). [RSAcalculator Light theme](https://www.cs.drexel.edu/~popyack/IntroCS/HW/RSAWorksheet.html) , [RSAcalculator Dark theme](https://www.tausquared.net/pages/ctf/rsa.html) 
The key variables that we need to know about for RSA in CTFs are p, q, m, n , e, d, and c.
"p" and "q" are large prime numbers, "n" is the product of "p" and "q". The public key is "n" and "e", while the private key is "n" and "d". 
"m" is used to represent the message (in plaintext) and "c" represents the ciphertext (encrypted text).
For hardcore math theory check [blogpost](https://muirlandoracle.co.uk/2020/01/29/rsa-encryption/)

# Digital Signatures
A digital signature is a way to prove the authenticity of files, to prove who created or modified them. Using asymmetric cryptography, we can produce a signature with our private key and it can bee verified using our public key. As only we should have access to our private key, this proves we signed the file.
The simplest form of this form of digital signature would be encrypting the document with our private key, and then if someone wanted to verify this signature they would decrypt it with our public key and check if the file match.

# Certificates
Certificates are also a use of public key cryptography, linked to digital signatures. A common place where they're used is for HTTPS. Each server has a certificate that says it is the real server that we are trying to access. These certificates have a chain of trust, starting with a root CA (certificate authority). Root CAs are automatically trusted by our device, OS, or browser from install. Certs below that are trusted because the Root CAs say they trust that organisation. Certificates below that are trusted because the organisation is trusted by the Root CA and so on. 

# SSH Authentication
By default, SSH is authenticated using usernames and passwords in the same way that we would log in to the physical machine. 
At some point, we are almost certain to hit a machine that has SSH configured with a key authentication instead. This uses public and private keys to prove that the client is valid and authorised user on the server. By default, SSH keys are RSA keys. We can choose which algorithm to generate, and/or add a passphrase to encrypt the SSH key. `ssh-keygen` is the program used to generate pairs of keys most of the time
## SSH Private Keys
A passphrase used to decrypt a private key isn't used to identify us to the server at all, all it does is decrypt the SSH key. The passphrases are never transmitted and never leave our system.
Using tools like [[John The Ripper]] we can attack an encrypted SSH key to attempt to find the passphrase, which highlights the importance of using a secure passphrase and keeping our private key private.
When generating an SSH key to log in to a remote machine, we should generate the keys on our machine and then copy the public key over as this means the private key never exists on the target machine. For temporary keys generated for access to CTF boxes, this doesn't matter as much
## How to use the keys
The `~/.ssh` folder is the default place to store these keys for OpenSSH. The `authorized_keys` file in this directory holds public keys that are allowed to access the server if key authentication is enabled. By default on many distros, key authentication is enabled as it is more secure than using a password to authenticate. Normally for the root user, only key authentication is enabled.
In order to use a private SSH key, the permissions must be set up correctly otherwise our SSH client will ignore the fiel with a warning. Only the owner should be able to read or write to the private key (600 or stricter).
```sh
ssh -i [keyNameHere] user@host
```
is how we specify a key for the standard Linux OpenSSH client

## Using SSH keys to get a better shell
SSH keys are an excellent way to upgrade a reverse shell, assuming the user has login enabled (www-data normally does not, but regular users and root will). Leaving an SSH key in `authorized_keys` on a box can be a useful backdoor, and we don't need to deal with any of the issues of unstabilised reverse shells like Control+C or lock of tab completion.

# Diffie Hellman Key Exchange
Key exchange allows 1 people to establish a set of common cryptographic keys without an observer being able to get these keys. Generally, to establish common symmetric keys.

Suppose that Alice and Bob want to talk securely. They want to establish a common key but they don't want to use asymmetric exchange, so they instead use DF key exchange.
Alice and Bobo both have secrets that they generate, A and B, they also have some common material that's public, G.
For this we need to make some assumptions. Firstly, whenever we combine secrets/material it's extremely difficult to separate and secondly, the order that they're combined does not matter.
Alice and Bob will combine their secrets with the common material forming AG and BG. They will then send these to each other and combine that with their secrets to form two identical keys, both ABG. 
## Math
Now, this works mathematically with the following
First, we are going to have two variables that are going to be public, $n$ and $g$. $g$ is often a small prime number and $n$ is an extremely large number often 2048 or even 4096 bits long. 
Now for both Alice and Bob, each will have a private variable that is going to be any number between 1 and $n$, let them be $a$ and $b$.
For the first step of the process both Alice will take $g$ and raise it her private variable $a$ and then take the mod of $n$
$$AG=(g^a) mod n$$ Bob will make the same procedure but with his own personal variable
$$BG=(g^b) mod n$$
Then the exchange happens, where Alice sends Bob $AG$ and Bob sends Alice $BG$, now they repeat the process that they did before with but substituting g with the received variable, so for Alice will be
$$ABG=(BG^a)modn$$
And for Bob 
$$ABG=(AG^b)modn$$
And they will receive the same key which they can then use as as their encryption key.

# GPG
Is an Open Source implementation of PGP (Pretty Good Privacy) from the GNU project, we may need to use [[GPG]] to decrypt files in CTFs. With GPG, private keys can be protected with passphrases in a similar way to SSH private keys. If the key is passphrase protected, we can attempt to crack this passphrase using [[John The Ripper]] and `gpg2john`.

# AES
Sometimes call Rijndael after its creators, stands for Advanced Encryption Standard. It was a replacement for DES which had short keys and other cryptographic flaws. 
AES and DES both operate on blocks of data. Broadly it works in a similar way to a Caesar cipher but instead of rotating each of the letters in a single direction, we arrange the bits in a grid to then make permutations to it horizontally and vertically to move the bits.