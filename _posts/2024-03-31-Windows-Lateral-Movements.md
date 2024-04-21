---
title: Windows Lateral Movements
date: 2024-03-31
categories:
  - red-team
  - windows
tags:
  - english
toc: "true"
---

In this post, we'll delve into **how Windows handles credentials to achieve SSO** and how we can capitalize on it. First, we'll discuss **the various types of authentications** available. Then, we'll explore **the realm of Logon Sessions**, understanding their purpose and function. Finally, we'll examine **Tokens** and how they can be leveraged to our advantage.

This post are mainly notes taken from the @attl4s investigation. The [Presentation 1](https://attl4s.github.io/assets/pdf/Understanding_Windows_Lateral_Movements.pdf)  [Presentation 2](https://attl4s.github.io/assets/pdf/Understanding_Windows_Lateral_Movements_2023.pdf) and [Recording 1](https://www.youtube.com/watch?v=a3qFsc9ApNs) [Recording 2](https://www.youtube.com/playlist?list=PLwb6et4T42ww94O3z5QDNQsO1f_BwhX-L) for this topic can be found in the linked words. Check his RRSS out, he has really great talks about all the Windows environment.

All that said, lets dig in. 

## Authentication

Authentication is the process of verifying the identity of a user or system. Windows has two main ways of authenticate users: **NTLM** and **Kerberos**.

### Types of authentication

- **Active or Physical Authentication**: This means that the user provides their username and password **directly on the Windows login screen**, typically when logging into a local computer or a computer within a network domain. No special privileges or additional steps are required, meaning that users don't need any special permissions or additional setup to use this authentication method. 
- **Passive or Remote Authentication**: authentication process occurs without direct user interaction or input on the host system they are trying to access. In this type of authentication, the user's credentials are verified remotely, often without the user's explicit involvement.

This distinction applies to both local authentications, which occur via the **Security Account Manager** (**SAM**), and authentications through **Active Directory** (**AD**), which is handled via the **NT Directory Service** (**NTDS**). When logging into a remote server as '**LocalHostname\user**', indicating a local user, special privileges are needed; local accounts are usually restricted to the machine they're created on and don't have privileges to log in remotely. Conversely, logging in as '**Corp\DomainUser1**' from a workstation does not necessitate any special privileges; it can be accomplished using the default account settings. However, if a whitelist has been implemented on that workstation, allowing access only to specific users, then additional considerations come into play.

### Authentication Packages

As mentioned earlier, there are two types of predominant authentications. Each of these uses a different DLL and its own flow.
#### Local authentication via Msv1_0 (NTLM):

In the process of **local authentication** via **Msv1_0 (NTLM)**, the user initiates the authentication sequence by sending a request to the **Security Account Manager (SAM)** of the host system. This request triggers a response from the host, which sends a **challenge** to the user.

Upon receiving the challenge, the user **signs** it using their **NTLM hash**, which is essentially a hashed version of their password. This signed challenge is then sent back to the system for **verification**. The system, in turn, verifies the signature by checking it against the user's credentials stored within the SAM.

> **Note**
> 
> Groups and specific users from Active Directory (AD) can be added as **local** administrators of a specific system. This does not mean that they authenticate over SAM.

> **Note**
> 
> As a default configuration, the **Domain Admins group** is automatically set as local administrators on all machines due to two specific policies activated on the **Domain Controller (DC)**.

In summary, the authentication process unfolds as follows: Users authenticate themselves on a system, whether through **physical or remote means**. The chosen authentication package then creates a **Logon Session**, incorporating the user's identity and pertinent security information. Finally, the **Local Security Authority Subsystem (LSASS)** generates a **security token** based on the Logon Session, encapsulating the user's security context and access rights.

## Logon Sessions

A **logon session** refers to the period of time during which a user is authenticated and authorized to access resources on a computer system. It begins when a user logs in or authenticates themselves to the system and ends when they log out or the session is otherwise terminated. The main purpose of logon sessions is to provide SSO.  

During a **logon session**, the system assigns the user **a set of security identifiers (SIDs)** and access **tokens**, which determine the user's permissions and rights to access various resources and perform specific actions within the system.

> **Important** 
> 
> Credentials stored in **memory** (as happens in **Physical Authentication**) are **ALWAYS** linked to a Logon Session.

There are two types of logon sessions:

- **Interactive** (not over the network)
- **Non-interactive** (remote)

**Logon sessions** differ depending on the user's privilege levels (also called integrity levels). Medium integrity processes are those running with normal user privileges, and high integrity processes are all those running as administrators. This differentiation requires creating two separate logon sessions for the same user.

> **Note**
> 
> Since Kerberos does not work with IPs, when you access a shared system folder (such as \10.10.10.10\C$), a non-interactive logon session authenticated by NTLM is created. This logon session is created on the 10.10.10.10 system. If you use the hostname or SPN instead of the IP, the authentication will be via Kerberos. 

In **interactive logon sessions**, **credentials** are typically **stored** temporarily in the system's **memory** during the authentication process. Once the user logs out or the session ends, these credentials are usually cleared from memory to enhance security.

On the other hand, in **non-interactive** scenarios where users access systems over a network, such as through a web application or remote desktop connection, the user's **credentials** may **not** be **stored** in **memory** on the local device. Instead, the authentication process typically involves authenticating over Kerberos or any other authentication mechanism to a remote server for verification. Once the authentication is complete, the server may issue a **session token** or other form of authorization to the client, but the actual credentials are not typically stored in the client's memory.

**Authentication** for **non-interactive** sessions works in such a way that the user has to prove they have those credentials **without sending them over the network**. This way, as they are not presenting the credentials but a prove that they have them, the credentials cannot be stored in memory (unless Kerberos delegation or specific options for certain types of authentication are used). 

> **Important**
> 
> Having **non-interactive** access to a system does not imply that we can access all resources of that system. Let me explain: Imagine we gain remote shell access to **host01** as a system **administrator**. In this scenario, since it's a **non-interactive session**, the credentials used for authentication **aren't stored in memory**. Because these credentials aren't stored, Single Sign-On (SSO) functionality isn't in play. Therefore, for any action on remote hosts requiring authentication, we must manually provide the username and password. If the credentials were stored in memory, we wouldn't need to specify them each time.

**LSA (Local Security Authority)** is pivotal in Windows, creating access tokens for local resource and application access, each token linked to a logon session. These tokens encapsulate user security context, including identity and privileges, ensuring secure resource interaction.

Every process/thread in Windows possesses a **unique access token** referencing a **logon session**, which dictates its permissions. However, the referenced logon session may or may not contain explicit credentials, depending on authentication method used for its creation.

More about tokens in the next section. 
## Access Tokens

Access tokens are data structures containing information about the identity and privileges associated with a user account.

Every process executed on behalf of a user has a copy of the token. A user can have several tokens, one for each "execution context."

Access tokens are used by Windows to implement access controls. Within Windows Security Descriptors of a specific object (e.g., a file), there's an attribute called the Discretionary Access Control List (DACL) containing a series of rules that define who has access to that specific resource and who doesn't. Access tokens are used by processes or threads to present an identifier to the operating system. The OS then checks if the User SID or groups are in the DACL of the resource or object and what permissions they have on it.

### Primary Tokens (Process Tokens)

These tokens serve as the basis for access control and authorization within the Windows environment. They determine what resources users and processes can access and what actions they can perform.

When a user logs in to a Windows system, a primary token is generated to encapsulate their security identity, including their security identifier (SID), group memberships, and privileges. 

Similarly, when a process is created, it inherits the primary token of its parent process or is assigned a new primary token based on the user context in which it is executed.

### Impersonation Tokens (Thread Tokens)

Allow threads to run in a different security context than the originating process. They are typically used in client/server scenarios (service accounts).

For instance, consider a database running under a service account. The database process's main thread inherits its Primary Token. However, when a user (e.g., User B) connects to the database, a new thread is spawned with an Impersonation Token **representing** User B. This mechanism ensures that access controls can be enforced when User B attempts to interact with specific tables in the database.

> **Note**
>
> As is a the User B is authenticating remotely, a new logon session is created. The impersonation token is referencing a this User B logon session. 

Generally, service accounts come with the **SeImpersonatePrivilege** and **SeAssignPrimaryPrivilege** privileges so that when a user connects to a service, it can create an Access Token impersonating them. This is what the **RottenPottato** vulnerability abuses.

Within impersonation tokens, there are four levels depending on the information within the token. We are only interested in tokens that fully impersonate the user (also called **Delegation Tokens**).

Delegation Tokens are associated with an interactive Logon Session, containing credentials in memory. Consequently, they can be leveraged to access remote resources, making them valuable assets in various authentication and authorization scenarios.

## User Impersonation

Impersonation is the ability of a thread to run in a different security context from the security context of the process it belongs to.

At this point, from an attacker's perspective, we can perform different actions depending on the credentials we gathered. 

### Do I have passwords?

Let's imagine we have found a password in a shared file. At this point, several things can be done.

The first one is to use **runas.exe**. This command is useful for lateral movements as it executes commands as other users. If you enter a machine as the user Pepe and you have Jesus' credentials, you can execute commands as Jesus. This is valid whether Jesus is a local user or a domain user; the important thing is that they have access to the system.

By default, runas.exe **executes commands locally**. To run commands **remotely**, it is necessary to **use the /netonly flag**. For example, consider this command:

``` powershell
runas.exe /user:capsule.corp\vegeta /netonly cmd
```

This command will prompt us for the credentials of the domain user vegeta and will open a cmd. This cmd is opened locally but with the peculiarity that if we try to interact with a remote resource or system, it will use the credentials we provided in the command. It is important to note that our system will not check if the credentials are correct; that is up to the remote system. Therefore, the logon session created when using the /netonly flag will not match the access token of the runas process.

When running runas with this flag, Windows creates a new logon session with the credentials we have indicated. Then it clones the access token of the process that ran runas and modifies it to refer to the new logon session. Finally, it creates a new process (in this case, cmd) and assigns that access token to it.

Runas prompts for credentials interactively, making it impossible to use via a reverse shell. Also, the use of runas may be logged in the system's logs and events.

The vast majority of C2 frameworks have their own implementation of runas through the Win32 API.

This executable creates an access token similar to the one created with an interactive logon, meaning that it stores the credentials in memory to implement SSO.

### What if I have a HASH?

#### Pass the hash in Windows

The steps are almost the same as those used by runas:

1. Create a new logon session.
2. Modify the hash of that new logon session (admin permissions are required).
3. Copy the original token and make it refer to the new logon session.
4. Use that token.

It's like runas /netonly but with the hash instead of the password.

In a normal procedure, a user would provide their credentials, and **LSASS** would create the **NTLM hash** to guarantee access to the host. By using Pass the Hash, you inject that hash directly into LSASS.

> **Note**
> 
> **Mimikatz** implements both **pass the hash** and **over-pass the hash**: once the NTLM hash is written into LSASS, it takes advantage of it for Windows to request TGS tickets.

### Pass the ticket

It operates similarly to pass the hash, but with **TGT** (Ticket Granting Ticket) tickets.
The Kerberos library facilitates this attack by enabling ticket importation without requiring administrative privileges, making it more accessible to attackers.

**Detection** of such attacks involves monitoring logon sessions for anomalies, such as the **presence of tokens** or **tickets belonging to different owners than the respective logon session.** This may indicate unauthorized access attempts and prompt further investigation and mitigation measures to prevent potential data breaches or system compromises."

#### ASK-TGT/TGS

Stands for "Ask for Ticket Granting Ticket/Ticket Granting Service." It refers to a step in the Kerberos authentication protocol where a client requests a Ticket Granting Ticket (TGT) from the Authentication Server (AS) in order to access the Ticket Granting Service (TGS).

It generates legitimate Kerberos traffic without the need for Windows to intervene, so it doesn't require being an administrator.

### What about tokens?

In the end, all the previous steps are necessary if we don't already have a token that interests us. A process that may interest us can be any process with an interactive session. Remember that for the token to have credentials in memory, it must be associated with an interactive logon session.

> **Note**
> 
> Manipulating tokens actions require local administrator permissions.

#### Token impersonation/theft

Basically, it consists of duplicating a token (that interests us) referring to a logon session with credentials. Then we assign this token to a new process or to a thread of a process that interests us. This can be achieved through the Win32 API.

### Injecting tokens with context

This second technique consists of injecting yourself into the context where the token you are interested in is. It involves injecting payload (which can be a DLL) into the process to which the token we are interested in is assigned. It can also be process hollowing, etc.