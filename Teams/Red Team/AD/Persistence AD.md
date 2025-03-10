We have [[Breaching AD|entered]] enemy territory. We have [[Enumerating AD|searched]] throughout the land. We have [[Lateral Movement and Pivoting|moved]] our forces. And we have [[Exploitation|conquered]] all. The only thing left for us is to maintain our newfound kingdom. While persistence is still a really important step it is not as time consuming or stressful as other phases. We have a plethora of ways that we can maintain persistence and since we have control of the system we can probably choose whichever we want.

# Credentials
The first and least reliable technique is credentials. Several of the [[Lateral Movement and Pivoting|lateral]] techniques would have resulted in us gaining access to credentials. This can be in the form of a user:pass pair or even by just having the hash we can authenticate through a PTT technique.

## DC Sync
It is often not enough to have a single DC per domain in large organizations. These domains are often used in multiple regional locations, and having a single DC would significantly delay any authentication services in AD. Thanks to this, organizations tend to make us of multiple DCs. Now, how are we able to authenticate using the same credentials in two different DCs?
It is thanks to **domain replication**. Each DC runs a process called the **Knowledge Consistency Checker** (KCC). The KCC generates a replication topology for the AD forest and automatically connects to other domain controllers through **Remote Procedure Calls** (RPC) to synchronize information. This includes updated information such as the user's new password and new objects such as when a new user is created. This is why we usually have to wait a couple of minutes before we authenticate after we have changed our password since the DC where the password change occurred could not be the same one as the one where we are authenticating to.
The process of replication is called DC Synchronization. It is not just the DCs that can initiate replication. Accounts such as those belonging to the Domain Admins groups can also do it for legitimate purposes such as creating a new DC.
This is where a popular attack comes up, the [DCSync Attack](https://blog.netwrix.com/2021/11/30/what-is-dcsync-an-introduction/). If we have access to an account that has domain replication permissions, we can stage a DCSync attack to harvest credentials from a DC.

## Credentials Are Made Different
Now, first we need to discuss what type of credentials we could hunt for. While we should always look to dump privileged credentials such as those that are members of the Domain Admins group, these are also the credentials that will be rotated first. So, if we only have privileged credentials, as soon as the blue team discovers us, they will rotate those accounts, and we could lose our access.
The goal in this case


# Tickets


# Certificates


# SID History


# Group Membership


# ACLs


# GPOs
