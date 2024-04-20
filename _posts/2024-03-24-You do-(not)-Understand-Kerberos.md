---
title: Understanding Kerberos
date: 2024-03-24
categories:
  - red-team
  - windows
tags:
  - english
  - Kerberos
toc: "true"
---

The goal of this post is to understand how Kerberos works and, most importantly, why it works the way it does. Kerberos is the primary authentication protocol in Active Directory, essential for securing Windows-based networks.

This post are the notes taken from the @attl4s presentation in Navaja Negra conference in 2019.
Here are the [Presentation](https://attl4s.github.io/assets/pdf/You_do_(not)_Understand_Kerberos.pdf) and [Recording](https://youtu.be/4LDpb1R3Ghg) for this theme. Check his RRSS out, he has really great talks about all the Windows environment.

All that said, lets dig in. 

# Protocol History

**Kerberos**, originating from the _Athena Project_ at MIT, emerged with the mission of simplifying computer access for students systematically. The vision was to enable **Single Sign-On (SSO)**, allowing users to authenticate once and maintain access for a specified period, typically eight hours. This system aimed to provide seamless access to network shares and DNS. Kerberos was born as a crucial component of this SSO approach.

> **Important**
> 
> **Kerberos** primarily functions as an **authentication** protocol, **NOT** as an **authorization** mechanism. Essentially, it provides users with a digital identity, similar to a identification card, but it does not grant inherent access to all resources.

Initially released in 1989, **Kerberos** used DES encryption. Over time, it evolved into **Kerberos v5**, which received a significant update in 2005. This version introduced several improvements, including the **Generic Security Services Application Programming Interface (GSS-API)**, support for cross-domain authentication, protocol extension capabilities, additional encryption options, and the adoption of **ASN.1**.

The significance of **Kerberos** was further highlighted when **Microsoft** showed interest in it during the 2000s as a replacement for **NTLM (NT LAN Manager)**. Microsoft's incorporation of the **Security Support Provider Interface (SSPI)** and subsequent protocol updates in 2006 marked a notable milestone in Kerberos' journey, demonstrating its relevance beyond academic environments towards conventional enterprise authentication systems.

# Design

**Reference**: [Kerberos Dialogue](https://web.mit.edu/kerberos/dialogue.html)

Originating from the groundbreaking _Athena Project_ at MIT, Kerberos emerged with a clear mission in mind: to streamline computer access for students systematically. The problem being addressed was the shared use of computers among many people, prompting the need for a solution that would enable secure authentication without the complexity of separate password databases for each service.

So the idea of a central authentication server came up. At its core, Kerberos functioned as a pivotal element of the Single Sign-On (SSO) paradigm, seamlessly facilitating access to network shares and DNS services.

Okay, but how does a person like Charles, for example, use a mail service? Somehow, he has to let the mail service know that he has authenticated correctly against Kerberos...

Then a concept called the **Service Ticket** or **ST** appeared. It works with a symmetric key scheme, and it works as follows:

> **Note**
> 
> This first approach does not take into account the Key Exchange mechanism; It is assumed the symmetric session key is passed from the user through a secure channel to the Kerberos server. 

1. Charles sends a ticket with a timestamp encrypted with his symmetric session key (derived from his password) and his username to the Kerberos server.
2. The Kerberos server tries to decrypt the timestamp with the username' symmetric key. If successful, the server sends a **Service Ticket** back to Charles. This ticket contains his **identity**: Name, groups, attributes, etc. This identity is encrypted with the secret key of the service we want to access, in this case, the mail service. 

> **Note**
> 
> Charles cannot decrypt the ticket because he does not have the key to the mail service; only the Kerberos server and that particular service have the secret key.

3. Charles then sends this ticket to the service, and if it can decrypt it, it will read our identity and grant us access to our mail.

This is cool, but it is not how Kerberos actually works. With this approach Charles would have to enter the password every time he wants to access a service, therefore SSO is not implemented. If he wishes to check his email again or access a different service, he'll need to re-enter the password each time. To solve this, **Ticket-Granting Tickets** (**TGTs**) were born.

So far, what we've seen is the Kerberos component called "**Authentication Service**" or **AS**. TGT is managed by another different part: the "**Ticket Granting Service**" or **TGS**. Together they work as follows:

**Step 1**. Charles sends a **Timestamp** encrypted with the his session key and its User-ID to the **AS**.
**Step 2**. If the **AS** can decrypt the timestamp, sends to Charles a **TGT**, which contains Charles' identity, but this time encrypted with the secret key of the **TGS**. It also sends charles the next session key to encrypt the TGS Request. 
**Step 3**. Now when Charles wants to access any service (for example, the mail service) he only has to send this **TGT** to the **TGS** service of the Kerberos server. Since no additional encryption is necessary, there's no need to request credentials again!
**Step 4**. The **TGS**, upon receiving this **TGT**, will try to decrypt it. Upon successful decryption, it will read Charles' identity and the service he wants to access. Then, It will send back a **Service Ticket** (**ST**) with Charles' identity and encrypted with the secret key of the service he wants to access.
**Step 5**. Now Charles can access to access the service he indicated earlier with this **ST**.

In summary, **TGTs** serve to implement **SSO**, obtaining **Service Tickets** without needing to provide the password each time.

## Tickets

Certainly, tickets cannot remain valid indefinitely. If a ticket were to fall into the wrong hands, it could potentially be misused to impersonate another identity indefinitely. Hence, tickets are designed to be both reusable and renewable until a predetermined deadline specified by the **Timestamp** contained within the ticket.

When a ticket is presented to a service (whether the **TGT** to the **TGS** or the **ST** to whichever service), it performs the following actions:

1. Decrypts the ticket,
2. Confirms the expiration date,
3. Verifies that the "**principal**" (the identity) has privileges to use the service.

Tickets can be used to **impersonate** another person's identity since services cannot determine if the person delivering it is the owner of that ticket's identity.

*How can we verify that a user is the legitimate owner of that ticket?* 
MIT tried to find a way to solve this with "**Authenticators**."
## Authenticators

**Authenticators** are data structures that include our **identity**, the **timestamp** (to not be reused), and is **encrypted** (with the secret key of the service). This way, we can ensure that no one can use the ticket on behalf of another person.

**Authenticators** are encrypted with session keys provided by the **AS** (or **TGS**) services. These two services send to the client a copy of the session key along with the ticket. In this message they also include another copy of the session key within the ticket. The session key copy sent by the **AS** along with the **TGT** is encrypted with our secret key, while the the session key sent by the **TGS** along with the **ST** is encrypted with the symmetric key of the service to which we are presenting the **Authenticator** and the **ST**. This can be better understood with the following image:

![Kerberos authentication](/assets/img/posts/kerberos/Kerberos_protocol.png)  _Kerberos negotiation_

As previously seen, the execution flow that the service follows when it receives a ticket is as follows:

1. Decrypt the ticket,
2. Extract the session key from the ticket,
3. Use the session key to decrypt the **Authenticator**,
4. Confirm that the ticket is being used by its owner.

# Kerberos in AD

Now let's see how Kerberos works in Active Directory. Things don't really change much, but there are certain aspects to consider:

- First, Kerberos **requires** that all actors using it have the **same time source**; otherwise, the tickets issued may expire prematurely or be issued already expired. That's why Domain Controllers have the NTP service.

- Kerberos operates on port 88 using both TCP and UDP. TCP is recommended.

- Kerberos does **not** work with **IP** addressing; it relies on DNS names to issue the STs. In the latest versions of Windows, Kerberos clients can be configured to support both IPv4 and IPv6 addresses in SPNs.

## Components

- The **Kerberos server** is the **Domain Controller**.
- The **database** where credentials are stored is called **NTDS**.
- The **AS** and **TGS** services are collectively referred to as the **Key Distribution Center** or **KDC**.
- Every **participant** in Kerberos is called **Principals**.
- All **computers** participating in Kerberos are called **servers**, including **service accounts**.

### servicePrincipalName (SPN)

Kerberos implements its services through an attribute called **servicePrincipalName** or **SPN**. This attribute allows registering Kerberos services on domain accounts.

Each **SPN** consists of:
1. Service name
2. The host serving that service

For example:
`DNS/dc01.capsule.corp` - It is a DNS service offered by DC01 within the capsule.corp domain.

When requesting access to a specific service, its **SPN** must be specified in the request. For example, when requesting a **TGT** from the **AS**,  **SPN** will **always** be **krbtgt**/****\[Domain Controller]**.

### Messages

To conclude, AD provides the following names for message exchanges:

| Kerberos Message | Description                                                 |
| ---------------- | ----------------------------------------------------------- |
| AS-REQ           | Request for a Ticket-Granting Ticket (TGT) to the AS service. |
| AS-REP           | Response from the AS service to a TGT request.            |
| TGS-REQ          | Request for a Service Ticket (ST) to the TGS service.         |
| TGS-REP          | Response from the TGS service to a ST request.            |
| AP-REQ           | Request for mutual authentication between client and server.   |
| AP-REP           | Response for mutual authentication between client and server.  |
| Error            | Error message in case of authentication failure.      |

**Technical demo intercepting packets with Wireshark (Spanish)**: [YouTube Video](https://www.youtube.com/live/5uhk2PKkDdw?si=r7s3hQ8a70nzHOlv&t=3655)

Right after entering the credentials on your computer, a request is made to the **DC** to obtain a **TGT** in order to access the services offered by your computer!

> **Important remark**
> 
> When a user logs in to a domain computer, they can access local services on that computer (such as shared files, local printers, etc.) using the TGT obtained from the Domain Controller (DC) during login. **No TS is needed**.

> **Note**
> 
> TGTs and TSs are the same: a ticket. They have practically the same internal structure. TGTs allow you to authenticate locally and TSs allow you to access remote resources, but in general, they can be seen as the same thing with different properties. It can be seen as TS is just adding properties on top of TGT since some things have been added to it to make it usable for a specific service.

# (Ab)using Kerberos

There are several types of attacks against Kerberos. There are two main blocks:

| Credential Access      | User Impersonation |
| ---------------------- | ------------------ |
| User enumeration       | Ticket reuse       |
| Password enumeration   | Ticket forging     |
| "Roasting"             | Kerberos delegation   |

## Credential Access

### User Enumeration

**User enumeration** in the context of Kerberos can take advantage of how the authentication protocol works. When a client sends a Ticket-Granting Ticket (**TGT**) request to the AS service (**AS-REQ**), it includes the user's identity. If the user is valid, the KDC responds with a TGT; if not valid, the KDC returns an error message indicating that the identity is not recognized. Attackers can use tools like **Kerbrute** to send **AS-REQ** requests with a list of possible identities and observe the KDC's responses. If the KDC returns an error message, it means the identity does not exist; otherwise, if no error message is received, it means the identity is valid. This allows attackers to gather information about valid user identities in the domain.

### Password Enumeration

In the context of Kerberos, **password enumeration** can be carried out during pre-authentication (**AS-REQ**) requests. Attackers can attempt to send **AS-REQ** requests with incorrect passwords to perform a brute-force attack and try multiple password combinations until finding the correct one. It is important to note that this technique can be risky since the Domain Controller (DC) may have account lockout policies after a certain number of failed attempts. Therefore, a safer technique is "**password spraying**," which involves trying a small number of common passwords against multiple user accounts. It is important to note that the KDC does not generate event 4625, which is the typical event generated if you input incorrect credentials for a service, for example, SSH. However, there is an event for this specific case, which is event 4771 generated in case of pre-authentication failure; this event is generated by the KDC but is not enabled by default. These types of attacks can be performed using the Kerbrute tool.

### "Roasting"

Kerberos exchanges use a user's or service's secret key to encrypt certain parts of the messages.

If one of these messages is captured by listening to network communications or by forcing these users to emit one

 of these requests, we can attempt to crack the hashes and recover the secret keys. There are three types of roasting attacks:

- **AS-REQroasting**
- **AS-REProasting**
- **TGS-REProasting (or Kerberoasting).**

Kerberos supports different encryptions. By default, they are encrypted with AES256 with salt. Ideally, we should force tickets by pretending to be a service that only supports weaker encryption algorithms like RC4.

#### AS-REQroasting

AS-REQ requests with pre-authentication data contain a timestamp encrypted with a user's password. If we are on an unsegmented network, we can capture these requests and save them. Once obtained, we can take those timestamps and try to crack them. I encrypt the timestamp of the request with a password from a word list and compare it: if it matches any, then I have a found password.

This attack can be performed with JohnTheRipper. The hash format for this attack is as follows:

```
$krb5pa$18$<Principal_Name>$<REALM>$<SALT>$<CIPHER_BYTES>
$krb5pa$18$vegeta$CAPSULE.CORP$CAPSULE.CORPVegeta$<CIPHER_BYTES>
```

To extract the encrypted bytes from a **Wireshark** packet:
kerberos>as-req>padata>PA-ENC-TIMESTAMP>padata-value>cipher

> **Note**
> 
>To know the value of the salt, the AS-REP response must also be obtained. In Wireshark such as: kerberos>as-req>padata>PA-ENCTYPE-INF02>padata-value>salt (for correct requests)

#### AS-REProasting

These messages contain a TGT encrypted with the TGS service's symmetric key and a session key that will be encrypted with the user's password. If any AS-REP packet is captured, the session key can be attempted to be broken since it is encrypted with the user's password.

This attack can be performed with JohnTheRipper. The hash format for this attack is as follows:

```
$krb5asrep$18$<SALT>$<FIRST_BYTES>$<LAST_12_BYTES>
```

To extract the encrypted bytes from a Wireshark packet:
kerberos>as-rep>enc-part>cipher

This type of attack is especially interesting for domain accounts that have Kerberos pre-authentication disabled. This means that for that account, you can send the **AS-REQ** without credentials, and the **AS** service will return a **TGT** with the identity of another user (and encrypted with the **TGS** key) and a session key encrypted with that other user's password.

This means that for that user, you can force obtaining **AS-REP** requests without having to replay the **AS-REQ** requests.

Since we are forcing the request, we can indicate that we only support RC4, and therefore the AS service will have to pass the session key encrypted with the victim's password but with the RC4 algorithm. The hash format for this attack is as follows:

```
$krb5asrep$<Principal_Name>:<FIRST__16_BYTES>$<REMAINING_BYTES>
```
#### TGS-REProasting (Kerberoasting)

Requesting access to a service involves sending a TGS_REQ, which means that we have a TGT in our possession and, therefore, we are able to request an ST for any service (even if we do not have access).

Additionally, we know that a ticket (whether it's the TGT or an ST) is always encrypted with the symmetric key of the service it is directed to. Knowing this, we can consider cracking the TGS service keys or any other service keys.

> **Note**
> 
>There's a catch in all of this, and it's that the TGS service key is usually managed by the AD and tends to be an uncrackable key. That said, some admin might change the krbtgt user's password and set it to an insecure one.

The goal of Kerberoasting is to obtain STs and use them to crack the passwords of a service user.

Some services offer server or workstation accounts. The credentials for these accounts are managed by the AD itself and therefore tend to be long and random passwords (plus they are rotated). On the other hand, there are some services that need you to create a service account with a registered SPN for them. Therefore, these accounts are managed by people and may have insecure passwords.

Additionally, since we are forcing the request, we can indicate that we only support RC4, and therefore the TGS service will have to pass the TGS encrypted with the service account's password but with the RC4 algorithm.

> **Remember**
> 
>Obtaining a service key can open many doors even if that service is not in any administration group. Having the service key allows us to forge STs for that service for any identity. You can impersonate anyone in that service, and that person may have certain privileges within the server or the service itself.

## User Impersonation

### Ticket Reuse

TGT requests can be made using the following credentials:

- Username:Password
- NTLM Hash
- Kerberos Key

With this TGT, service tickets can be requested.

### Ticket Forging

With a service's password, we can decrypt, change, and re-encrypt a Service Ticket we have acquired for that specific service. This process is called forging.

**Golden Tickets**
Golden Tickets are forged TGTs. To do this, you need the krbtgt symmetric key.
A Golden Ticket can be forged with a non-existent user. With the Impacket Ticketer tool, you can forge one with any user you want and place it in Domain Admins (it does this by default).

**Silver Tickets**
Similar to Golden Tickets but for any other service other than krbtgt.

### Kerberos Delegation

As this is an large topic to talk about, it will have its own post.