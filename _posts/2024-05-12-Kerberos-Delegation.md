---
title: Kerberos Delegation
date: 2024-05-12
categories:
  - red-team
  - AD
tags:
  - english
toc: "true"
---
The goal of this post is to understand how Kerberos Delegation, how resolves the two-hop-problem and what attacks paths arise with bad implementations.

This post are the notes taken from the @attl4s presentation.
Here is the [Presentation](https://attl4s.github.io/assets/pdf/You_do_(not)_Understand_Kerberos_Delegation.pdf) and [Recording](https://www.youtube.com/watch?v=p9QFdITuvgU&list=PLwb6et4T42wyA0rhT0zFownoA9N8-6t1K&pp=iAQB) . Check his RRSS out, he has really great talks about all the Windows environment.

## What is Kerberos Delegation?
Kerberos delegation allows a service, like a web server, to obtain tickets on behalf of a user to access other services. It extends the user's authentication context to backend services, enabling seamless access without requiring the user's credentials to be transmitted. This mechanism ensures secure delegation of authentication and authorization, facilitating controlled access to resources.
## Why we need it?
Consider a scenario where you have a web application that utilizes Kerberos authentication for users to log in. Each user has their own set of data stored in a SQL database. Now, when a user logs in, the web server authenticates them via Kerberos. However, the web server faces a challenge: it needs to access the user's data from the SQL database. 

The problem arises because the web server, having authenticated the user, can't directly authenticate to the SQL database as that user. Traditional Kerberos authentication mechanisms don't provide a straightforward way for the web server to seamlessly act on behalf of the authenticated user to access their specific data in the SQL database. This is why Kerberos Delegation is created: the authentication flow from the web server to the SQL database lacks the necessary continuity to ensure that the user can only access their own data.
## How it works?
Kerberos delegation essentially extends the authentication context of the user to backend services like the SQL database. Traditionally, without delegation, the web server wouldn't have the necessary credentials to authenticate itself to the SQL database as the authenticated user.

Kerberos delegation resolves this issue by allowing the web server to obtain a service ticket from the KDC for the SQL service on behalf of the authenticated user. This service ticket contains the user's identity and grants the web server permission to access the SQL database using that identity.

With the obtained service ticket, the web server can securely communicate with the SQL database, presenting the user's identity as part of the authentication process. This enables the SQL server to trust the web server's identity, backed by Kerberos authentication.

Subsequently, the web server can retrieve the user's data from the SQL database and present it to the user through the web application. This entire process seamlessly extends the user's authentication context to backend services, ensuring that the user can only access their own data. 

## Types of Delegations
There are three ways to achieve Kerberos Delegation:

1. **Unconstrained Delegation**: This type allows a service to impersonate any user and access any service within the domain. While providing greater flexibility, it poses higher security risks, potentially enabling unauthorized access if compromised.
    
2. **Constrained Delegation**: Also known as S4U (Service-for-User) delegation, it permits a service to act on behalf of a user for a specific set of services. This limits the scope of delegation, enhancing security by reducing the risk of misuse.
    
3. **Resource-Based Delegation**: Resource-based delegation allows a service to delegate authentication requests based on the requested resource rather than the user's identity. It enhances security by ensuring that delegation occurs only when accessing specific resources, providing a more fine-grained control mechanism within Kerberos-enabled environments.

### Unconstrained Delegation
When a user authenticates to a service using Kerberos, that service can obtain a ticket-granting ticket (TGT) from the Key Distribution Center (KDC) on behalf of the user. With unconstrained delegation enabled, this service can then use the TGT to request service tickets for any other service in the domain, effectively impersonating the user.

Unconstrained delegation is generally discouraged unless absolutely necessary, and constrained delegation or resource-based delegation are preferred for more controlled and secure access delegation scenarios.

Here is how it works:

![Kerberos Unconstrained Delegation Flow](/assets/img/posts/kerberos/Unconstrained-Delegation.jpg)
_Unconstrained Delegation Flow_
_Source: [crowe.com](https://www.crowe.com/cybersecurity-watch/unconstrained-delegation-too-trusting-for-its-own-good)_

> **Note**
> 
> There are two missing steps in the diagram! The HTTP ST request and the actual ST presentation for accessing the HTTP service. Those steps would be between step 1 and 2, and inside step 3. Those steps are important because when the User asks for a ST for a service that is ok-as-delegate, the TGS service waits for the forwardable TGT request. 

1. The client requests a TGT ticket as seen in the [Understanding Kerberos](https://n10h0ggr.github.io/posts/You-do-(not)-Understand-Kerberos/) post.
2. The client requests a ST for the HTTP web service. The KDC notes that this service can delegate  credentals and therefore returns the ST with the `ok-as-delegate` attribute set to True. Seen that, the client requests a forwardable TGT and the KDC returns it. 
3. The client sends the HTTP ST and the Authenticator to the web server. Note that the forwardable TGT goes inside the Authenticator to protect it to be tampered or stolen. 
4. Once authenticated, asks for webpage content.
5. The web page service account requests a ST for the DB service with client identity to the KDC. Within the request sends the forwardable TGT as it contains the identity of the client; therefore the KDC will forge a ST for that identity and send it back to the web server. 
6. The web service now has the Service Ticket and sends it to the DB. The DB checks the identity and allows access to that identity data.
7. The DB sends the data to the web server.
8. The web can render the client data sent back form the DB service and can display the proper data to the client.

If we sniff the communication we would see something like this. Note that this packets are from a web server asking a SMB share and not a MSSQL. 

![Wireskark Unconstrained Delegation Flow](/assets/img/posts/kerberos/Wireshark-Unconstrained-Delegation.png)
_Unconstrained Delegation Packets_
_Source: [Attl4s](https://attl4s.github.io/assets/pdf/You_do_(not)_Understand_Kerberos_Delegation.pdf)_
#### Abusing unconstrained delegation
The major drawback of unconstrained delegation is its heightened security risk. Since the service can impersonate any user and access any service, if the service or its hosting server is compromised, attackers can potentially gain unfettered access to sensitive resources across the network.

Generally attacks to Unconstrained Delegation rely on the ability to add a service principal name (SPN) record for the account or add a domain name system (DNS) records. Next step is to force principals to connect to your Unconstrained Service, delivering forwardable TGTs and enabling you to craft STs for any service as that principal. 

To mitigate this impact constrained delegation arise, providing a more controlled approach by limiting the services that a service can access on behalf of a user. 
### Constrained Delegation

As explained, constrained delegation provides a more controlled and secure approach by limiting the services that a service can access on behalf of a user. By specifying the allowed services, administrators can restrict access to only necessary resources, reducing the attack surface and minimizing the risk of unauthorized access. 

Enabling an account to use constrained delegation requires high privilegies (**Domain** or **Enterprise Admin** permissions). To activate it, the account shall have the `SeEnableDelegation` attribute set as true.

To implement constrained delegation two extensions were added; those were called the S4U2 extensions. There are 2 types: the S4U2Self and the S4U2Proxy:
- **S4U2Self**: This extension allows a service to obtain a service ticket for itself on behalf of a client as evidence that the client has connected. Any service can use this. 
- **S4U2Proxy**: This extension allows a service to obtain a service ticket for a client for a different service. To perform such operation requires a service ticket as evidence that the client has connected.

With those extensions, Constrained Delegation can be configured in two ways, only using S4U2Proxy and using S4U2Proxy and S4U2Self. The usage of one or two extensions will depend on how the user authenticates against the service who needs to delegate those credentials. Mainly are two types:
1. **Kerberos only**: The client authenticates via Kerberos. To delegate the credential it only need S4U2Proxy extension.
2. **Protocol transition**: Regardless of how the client connects, the service will be able to delegate credentials. It needs both, S4U2Self and S4U2Proxy extensions combined.

> **Important**
> 
> It is essential to understand that in unconstrained delegation, it's the client that delegates the TGT to the service, but in unconstrained delegation with S4U2Proxy, the client delegates its ST to the service. 

#### Kerberos Only

For this type of delegation we assume that the client authenticates to the service as usual, presenting the pertinent ST. The main process is as shown:

![Kerberos Only Constrained Delegation](/assets/img/posts/kerberos/Constrained-Delegation.jpg)
_Constrained Delegation Flow_
_Source: [crowe.com](https://www.crowe.com/cybersecurity-watch/constrained-delegation-resource-based-delegation-outsmart-attacks)_

3. The web service account (User A) requests a ST for the DB service for the client (user P). To achieve that sends User A TGT and User P ST (the one used for accessing web service). The ST is sent as a prove that the user P has connected to the service and to know the identity that the new ST shall be emmited. 
4. The TGS checks if the ST is marked as Forwardable and if web service account (User A) can delegate to DB service account (User B); this is checked in the `mdDS-AllowedToDelegateTo` attribute of User A account, as it shall have User B account in its value. 
5. The web service sends the User P ST to the DB to be authenticated. 
6. The DB sends the data.

Sniff the communication would show us something like the following. Note that this packets are from a web server asking a SMB share and not a MSSQL. 

![Wireshark-Kerberos-Only-Constrained-Delegation.png](/assets/img/posts/kerberos/Wireshark-Kerberos-Only-Constrained-Delegation.png)
_Kerberos-Only Constrained Delegation Packets_
_Source: [Attl4s](https://attl4s.github.io/assets/pdf/You_do_(not)_Understand_Kerberos_Delegation.pdf)_

> **Note for trubleshooting**
> 
> When using this type of delegation in IIS the Kerberos Delegation with DFS Share the delegation settings have to be specified twice, one for the Share account and another for the IIS machine account. 

Kerberos-only constrained delegation just requires the user's ST (that must be "forwardable") to allow a service to request  service tickets for that user. As a difference, here is the service who requests the ticket and not the user.

Next casuistic is when the user is not authenticated to the service using Kerberos and therefore the service cannot present the client ST to the KDC. 

### Using Protocol Transition

This configuration is a way to use the service without providing evidence that the client has connected. 

This protocol uses both S4U2 extensions. The process is pretty the same as in the previos Kerberos only:

![Wireshark-Protocol-Transition-Constrained-Delegation.png](/assets/img/posts/kerberos/Wireshark-Protocol-Transition-Constrained-Delegation.png)
_Protocol Transition Constrained Delegation Packets_
_Source: [Attl4s](https://attl4s.github.io/assets/pdf/You_do_(not)_Understand_Kerberos_Delegation.pdf)_

The process works as follows: 

1. The client successfully authenticates with NTLM.

2. **S4U2Self**: The objective is to obtain a Service Ticket for its own service on behalf of the client to use it to invoke the S4U2Proxy process. The service sends its own TGT and the client's principal to the KDC. The KDC checks if the service invoking the request is trustworthy (it shall have the `trusted_to_auth_for_delegation` attribute activated). Then sends the ticket with the "forwardable" feature set as True; without this feature, the ticket will not be valid. If all conditions are met, the TGS responds with an ST on behalf of the client for the service itself (the HTTP service in this case).

3. **S4U2Proxy**: The service requests an ST on behalf of the client for a second service and sends the client ST used to authenticate to the requester service as evidence that the client has authenticated. The KDC checks if the service for which the ST is being requested is within the `mdDSmdDS-AllowedToDelegateTo` attribute. If everything is in order, it sends the ST. Now the service can use that ticket to connect to the service on behalf of the client.

In protocol transition, the service has independence: with just the principal, it can request an ST for any user for any service, as the service to which the ST is directed is in plaintext for the service.

#### Abusing protocol transition
An account configured with Protocol Transition can invoke S4U2Self to impersonate any user and obtain a Forwardable ST to be used with S4U2Proxy. Even if `msDS-AllowedToDelegateTo` is configured with specific services of a service account, you can modify the Forwardable ST to target others from the same service account. This is because the service name of a ST is in plaintext and can be substituted. Example: `cifs/sql01.capsule.corp → HTTP/sql01.capsule.corp`

When invoking S4U2Proxy with a "non-forwardable" ST, an error occurs, and it falls back to Resource-Based Constrained Delegation (RBCD). This casuistic was not explained in Microsoft documents and security researchers started investigating. We will aboard how Resource-Based Constrained Delegation works in next section.

### Resource-Based Constrained Delegation
The fist notable difference is that to configure this type of delegation, Domain or Enterprise Admin permissions are not required. The only prerequisite is to have write permissions on `ms-DS-AllowedToActOnBehalfOfOtherIdentiry` of a service account. 

The next difference is that the trust bond is configured in the service receiving the credential delegation. In our example that is the MSSQL service is where trusty relations must be configure.

The RBCD flow is very similar as in Protocol Transition, the only difference is that as the service who is making the request is not marked as `trusted_to_auth_for_delegation`, then the KDC delivers a non-forwardable ST from the S4U2Self process. The HTTP service then will start the S4U2Proxy process using an invalid ST, which makes the KDC use RBCD as a fallback.

RBCD comes into play when the service does not have Constrained Delegation configured. 

When the service requests the KDC for a ST for its own service on behalf of the client, it sees that the service is not trusted (the `trusted_to_auth_for_delegation` is not activated, and thus unconstrained delegation is not active). The TGS sends a non-forwardable. The process follows as in the image:

![Kerberos authentication](/assets/img/posts/kerberos/Resource-Based-Constrain-Delegation.jpg)
_RBCD Flow_
_Source: [crowe.com](https://www.crowe.com/cybersecurity-watch/constrained-delegation-resource-based-delegation-outsmart-attacks)_

3. The service begins the S4U2Proxy flow with the service account TGT and the non-forwardable ST. It requests a new ST for the DB service with the client identity. 
4. The KDC, upon seeing this non-forwardable ST, checks if the service that made the request is trusted for the service the ST is being requested for. If it is trustworthy, everything is okay, and it sends a valid ST for this second service on behalf of the client.
5. The web service sends the ST to the DB to be authenticated. 
6. The DB sends the data.

The exchanged packets shall be as follows (Remember that this packets are from a web server asking a SMB share and not a MSSQL):

![Wireshark-Protocol-Transition-Constrained-Delegation.png](/assets/img/posts/kerberos/Wireshark-Protocol-Transition-Constrained-Delegation.png)
_RBCD Packets_
_Source: [Attl4s](https://attl4s.github.io/assets/pdf/You_do_(not)_Understand_Kerberos_Delegation.pdf)_
#### Abuse RBCD
In RBCD, you cannot need to change the service name in the ST as in Constrained Delegation; you can simply obtain an ST for any service that trusts you. Most interestingly, it does not require DomainAdmin or Enterprise Admin permissions.

RBCD attacks are often used to escalate their privileges within the system, potentially gaining access to sensitive data or resources. Impersonate legitimate users with specific roles assigned to them may enable to chane permissions in other accounts or enable other type of attacks.  There are plenty of interesting attacks regarding RBCD abuse, I encourage you to check this:
- [Elad Shamir - Wagging the Dog: Abusing Resource-Based Constrained Delegation to Attack Active Directory](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [Simone Salucci & Daniel López Jiménez - Kerberos RBCD: When an Image Change Leads to a Privilege Escalation](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)


## How to Protect Yourself
To protect your organization against attacks targeting RBACD, you can leverage the capabilities of the Protected Users group along with specific User Account Control (UAC) settings.

Firstly, by incorporating sensitive accounts into the Protected Users group, such as privileged users or service accounts, you enforce heightened security measures. Membership in this group ensures that the Kerberos Key Distribution Center (KDC) refrains from setting the PROXIABLE or FORWARDABLE ticket flags for their tickets. Consequently, attackers are thwarted from exploiting these flags to elevate privileges or execute lateral movement within the network.

Additionally, configuring UAC settings to mark accounts as sensitive and restrict delegation of credentials is imperative. This step prevents sensitive accounts from being delegated, thus minimizing the risk of unauthorized access or credential misuse. By implementing these measures, particularly for privileged accounts, you effectively block attackers from leveraging services for user-to-self (S4U2Self) or user-to-proxy (S4U2Proxy) delegation, bolstering overall security. Regular review and updating of these configurations are essential to adapt to evolving threats and maintain a resilient defense against potential security breaches. Moreover, continuous monitoring and auditing of RBACD configurations are critical for detecting and responding to any unauthorized activities or attempts to exploit system vulnerabilities.

## Interesting Links

- Dirk-Jan Mollema - [“Relaying” Kerberos - Having fun with unconstrained delegation](https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/)
- Roberto Rodriguez – [Hunting in Active Directory: Unconstrained Delegation & Forests Trusts](https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1)
- Crummie5 - [Kerberos Unconstrained Delegation: Compromising a Computer Object by its TGT](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)