It is a Windows-based directory that stores and provides data objects to the internal network environment. It allows for centralized management of authentication and authorization. The AD contains essential information about the network and the environment including users, computers, printers, etc. AD might have user's details such as job title, phone, number, address, passwords, groups, permissions, etc.

# Glossary
- **Domain controllers**: A domain controller is a windows server that provides AD services and controls the entire domain. It is a form of centralized user management that provides encryption of user data as well as controlling access to a network, including users, groups, policies and computers. It also enables resource access and sharing.
- **Organizational Unit (OU's)**: These are containers within the AD domain with a hierarchical structure.
- **Active Directory Objects**: can be a single user or a group, or hardware component, such as a computer or printer. Each domain holds a database that contains object identity information that creates an AD environment, including Users, Computers, and GPOs
- **AD domains**: are a collection of Microsoft components within an AD network
- **AD Forest**: is a collection of domains that trust each other
## Accounts
An AD environment contains various accounts with the necessary permissions, access, and roles for different purposes. Common AD service accounts include built-in local user accounts, domain user accounts, managed service accounts, and virtual accounts.
- The built-in local user's accounts are used to manage the system locally, which is not part fo the AD environment.
- Domain user accounts with access to an active directory environment can use the AD services
- AD managed service accounts are limited domain user accounts with higher privileges to manage AD services
- Domain Administrators are user accounts that can manage information in an AD environment, including AD configurations, users, groups, permissions, roles, services, etc. 
The following are AD administrator accounts

| BUILTIN\Administrator | Local admin access on a domain controller                  |
| --------------------- | ---------------------------------------------------------- |
| Domain Admins         | Administrative access to all resources in the domain       |
| Enterprise Admins     | Available only in the forest root                          |
| Schema Admins         | Capable of modifying domain/forest; useful for red teamers |
| Server Operators      | Can manage domain servers                                  |
| Account Operators     | Can manage users that are not in privileged groups         |

# Enumeration
For this we are going to be using mainly `PowerShell` to enumerate for users and groups

## Accounts
We can get all active directory user accounts with 
```powershell
Get-ADUser -Filter *
```
This will throw a list of users within the AD environment. The Distinguished Name (DN) is a collection of comma-separated key and value pairs used to identify unique records within the directory. The DN consists of Domain Component (DC), OrganizationalUnitName (OU), Common Name (CN), etc. See [this](https://www.ietf.org/rfc/rfc2253.txt) for more info.
Using the `SearchBase` option, we can specify a DN in the active directory to search for certain results
```powershell
Get-ADUser -Filter * -SearchBase "CN=Users,DC=company,DC=com"
```

# Authentication
## Kerberos

## NetNTLM
