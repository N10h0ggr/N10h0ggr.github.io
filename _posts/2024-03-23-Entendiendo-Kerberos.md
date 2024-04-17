---
title: Entendiendo Kerberos
date: 2024-03-23
tags:
  - Kerberos
  - spanish
toc: "true"
---

**Referencias**: https://attl4s.github.io/

El objetivo es entender como funciona Kerberos y, lo mas importante, por que funciona así. 
Kerberos es el principal protocolo de autenticación en directorio activo. 

| **Remark**                                                                                                                                                                                                                                                                                                                                                                                                             |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Durante estos apuntes menciono veces que la clave simétrica que utiliza Kerberos es la password del usuario. Esto no es bien bien así. Obviamente Kerberos no utiliza la password del usuario porque el tamaño de clave es muy inconsistente y restrictivo para esquemas de clave simétrica, por lo que las claves que utiliza Kerberos **se derivan** de la password del usuario, pero en ningún momento es la misma. |

# Historia del protocolo

**Kerberos**, originado del *Proyecto Athena* en MIT, surgió con la misión de simplificar el acceso a las computadoras para los estudiantes de manera sistemática. La visión era permitir el **Inicio de Sesión Único (SSO)**, lo que permite a los usuarios autenticarse una vez y mantener el acceso durante un período establecido, típicamente ocho horas. Este sistema tenía como objetivo proporcionar acceso a recursos compartidos de red y DNS de manera fluida. Kerberos nació como un componente crucial de este enfoque SSO.

| **Importante**                                                                                                                                                                                                                                                                                         |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Kerberos** funciona principalmente como un protocolo de **autenticación**, **NO** como un mecanismo de **autorización**. En esencia, proporciona a los usuarios una identidad digital, similar a una tarjeta de identificación nacional (DNI), pero no otorga acceso inherente a todos los recursos. |

Inicialmente lanzado en 1989, **Kerberos** utilizaba cifrado DES. Con el tiempo, evolucionó hacia **Kerberos v5**, que recibió una actualización significativa en 2005. Esta versión introdujo varias mejoras, incluida la **Interfaz de Programación de Aplicaciones de Servicios de Seguridad Genéricos (GSS-API)**, soporte para autenticación entre dominios, capacidades de extensión del protocolo, opciones de cifrado adicionales y la adopción de **ASN.1**.

La importancia de **Kerberos** se destacó aún más cuando **Microsoft** mostró interés en él durante la década de 2000 como reemplazo de **NTLM (NT LAN Manager)**. La incorporación de **Microsoft** de la **Interfaz de Proveedor de Soporte de Seguridad (SSPI)** y las actualizaciones posteriores del protocolo en 2006 marcaron un hito notable en el viaje de **Kerberos**, demostrando su relevancia más allá de los entornos académicos hacia sistemas de autenticación empresarial convencionales.

# Diseño

**Referencia**: [Diálogo de Kerberos](https://web.mit.edu/kerberos/dialogue.html)

El problema que se intenta resolver es que, en aquella época, se estaba utilizando un mismo ordenador para muchas personas. Se planteó tener tantos ordenadores como estudiantes para que no tuvieran que compartir; además, se conectarían entre ellos. 

En un momento del diálogo de Kerberos, Eurípides deja entrever a Atenea que la idea está genial, pero como no hay autenticación, va a hacer pasar por ella y le va a borrar los archivos y va a hacer cosas malas en su nombre, dado que nadie tiene ninguna manera de saber quién está haciendo esas acciones. De ahí nace la necesidad de la autenticación.

De primeras sale la idea de pedir usuarios y contraseñas que validaría cada servicio por separado. Para utilizar cada uno de los servicios se deberá introducir la contraseña, lo que significa que cada uno de esos servidores donde se aloja un servicio debería tener su propia base de datos de contraseñas. Esto es muy costoso y muy difícil de mantener.

Entonces se pensó la idea de un servidor central de autenticación. Cualquier persona, servicio, agente, workstation... se deberá identificar ante el servidor de Kerberos mediante credenciales.

Vale, pero ¿cómo utiliza una persona como, por ejemplo, Charles, un servicio de correo? De alguna manera tiene que hacerle saber al servicio de correo que se ha autenticado de manera correcta contra Kerberos, y de la misma manera Charles debe saber que ese servidor de correo al que se esta conectando, se ha autenticado de manera correcta y es quien dice ser.

Entonces apareció un concepto llamado el **Service Ticket** o **ST**. Funciona con un esquema de clave simétrico de la siguiente manera:

1. Charles envía al servidor de Kerberos un ticket cifrado con su clave simétrica (su contraseña). Este ticket contiene un Timestamp.
2. El servidor de Kerberos intenta descifrarlo con la clave simétrica de Charles. Si lo consigue, el servidor envía un **Service Ticket** de vuelta a Charles. Este ticket contiene su identidad: Nombre, grupos, atributos, etc. Y va cifrado con la clave única del servicio al que queremos acceder, en este caso, el correo. Date cuenta de que Charles no puede descifrar el ticket dado que no tiene la clave del servicio de correo; esa clave solo la tienen el servidor de Kerberos y ese servicio en particular.
3. Charles entonces envía este ticket al servicio y si este consigue descifrarlo leerá nuestra identidad y nos dará acceso a nuestro correo.

Esto está guay, pero entonces Charles tendría que poner la contraseña cada vez que quiera acceder a un servicio. Si quiere volver a consultar el correo deberá volver a poner la contraseña y si quiere acceder a otro servicio diferente, también. Para solucionar esto nacen los **Ticket-Granting Ticket** o **TGTs**.

Hasta ahora lo que hemos visto se denomina "Authentication Service" o **AS**. La parte que incorpora el **TGT** se denomina "Ticket Granting Service" o **TGS**. En conjunto funcionan de la siguiente manera:

1. Charles envía su sobre con el **Timestamp** cifrado con su contraseña (su clave simétrica) al **AS** del servidor de Kerberos.
2. Si el servidor puede descifrar este sobre, envía a Charles un **Ticket-Granting Ticket** o **TGT**, que contiene la identidad de Charles, pero esta vez está cifrado con la clave simétrica del servicio **TGS** del servidor de Kerberos.
3. Ahora cuando Charles quiera acceder a cualquier servicio (por ejemplo, al de correo) solo tendrá que enviar ese **TGT** (junto con los datos del servicio al que quiere acceder) al servicio **TGS** del servidor de Kerberos. Como no hay que volver a cifrar nada, ¡no se tiene que volver a pedir las credenciales!
4. El **TGS** al recibir este **TGT** lo intentará descifrar. Al descifrarlo correctamente, leerá la identidad de Charles y el servicio al que quiere acceder. Una vez validado, nos dará un **Service Ticket** o **ST** con nuestra identidad y cifrado con la clave simétrica del servicio al que queremos acceder.
5. Charles puede utilizar este ticket para acceder con su identidad al servicio que ha indicado anteriormente.

En resumen, los **TGTs** sirven para implementar el **SSO**, consiguiendo **Service Tickets** o **STs** sin necesidad de saber la contraseña.

## Tickets

Evidentemente, los tickets no pueden durar toda la vida. Si alguien robara un ticket podría hacerse pasar por otra identidad de por vida. Por lo tanto, los tickets son reusables y renovables hasta una fecha límite concreta indicada por el **Timestamp** dentro del ticket.

Cuando se presenta un ticket a un servicio (ya sea el **TGT** al **TGS** o el **ST** al servicio que sea) hace las siguientes acciones:

1. Descifra el ticket
2. Confirma la fecha de expiración
3. Comprueba que el "principal" (la identidad) tiene privilegios para utilizar el servicio

Los tickets se pueden utilizar para suplantar la identidad de otra persona dado que los servicios no pueden determinar si quien lo entrega es el propietario de la identidad de ese ticket.

¿Cómo podemos comprobar que un usuario es el propietario legítimo de ese ticket? El MIT intentó encontrar una manera para solventar esto con los "Authenticators".

Los "Authenticators" son unas estructuras de datos que incluyen nuestra identidad, el **Timestamp** (para la caducidad) y otras cosas. La idea era que cuando un cliente intenta utilizar un **TGT** o un **TGS** no solo debe enviar el ticket en sí, sino que también deberá enviar un "Authenticator" cifrado. Recuerda que las identidades de los tickets no se pueden manipular ya que van cifradas. La idea era que los servicios compararan las identidades del ticket y del "Authenticator".

Estos "Authenticators" van cifrados con unas claves de sesión que nos proporciona el servicio **AS** (o **TGS**) del servidor de Kerberos. Estos dos servicios envían una copia de la clave de sesión junto con el ticket al cliente y además incluyen otra copia de la clave de sesión dentro del ticket. La copia de la clave de sesión que nos envía el **AS** junto con el **TGT** va cifrada con nuestra clave simétrica, mientras que la copia de la clave de sesión que nos envía el **TGS** junto con el **ST**, va cifrada con la clave simétrica del servicio al que vamos a presentar el "Authenticator" y el **ST**.

Por lo tanto, ahora el flujo de ejecución que sigue el servicio cuando le llega un ticket es el siguiente:

1. Descifra el ticket
2. Extrae la clave de sesión del ticket
3. Usa la clave de sesión para descifrar el **Authenticator**
4. Confirma que el ticket está siendo utilizado por su propietario.

| **Recuerda**                                                                                                               |
| -------------------------------------------------------------------------------------------------------------------------- |
| Este flujo de ejecución sirve tanto para los servicios que utilizan los **ST** como para el servicio **TGS** que utiliza los **TGTs**. |

**Explicación grafica completa:** [Video en YouTube](https://www.youtube.com/live/5uhk2PKkDdw?si=HvcdX6CiZh2vcRqv&t=2680)

Tal y como se ve en el video, existe una manera de autenticar a los servicios, pudiendo comprobar nosotros que son quienes dicen ser.

# Kerberos en AD

Ahora veremos como actúa Kerberos en Directorio Activo. Realmente no cambia mucho la cosa pero si que hay ciertos aspectos a tener en cuenta: 

- Para empezar, Kerberos necesita que todos los actores que lo utilizan tengan la misma fuente de tiempo, sino, los tickets que se emitan pueden caducarse prematuramente o emitirse ya caducados. Por eso los Domain Controllers tienen el servicio NTP. 

- Kerberos funciona en el puerto 88 en el puerto TCP y UDP. Normalmente y lo recomendado es TCP.

- Kerberos no trabaja con direccionamiento IP, se sustenta en los nombres de DNS para emitir los STs. En las versiones mas recientes de Windows, los clientes de de Kerberos se pueden configurar para soportar direcciones IPv4 y IPv6 en SPNs.

## Componentes 

El servidor de Kerberos pasa a llamarse Domain Controler.
La base de datos donde se almacenan las credenciales pasa a llamarse NTDS
Los servicios AS y TGS pasan a llamarse en conjunto como Key Distribution Center o KDC
Todo participante de Kerberos se va a llamar Principals
Todos los ordenadores que participen en Kerberos se van a llamar servidores, incluidas las cuentas de servicio. 

### servicePrincipalName (SPN)

Kerberos implementa sus servicios a traves de un atributo denominado servicePrincipalName o SPN. Este atributo permite registrar los servicios de Kerberos en cuentas de dominio.

Cada SPN consiste de:
1. Nombre de servicio 
2. El host sirviendo ese servicio 

Por ejemplo:
DNS/dc01.capsule.corp -> Es un servicio DNS ofrecido por DC01 dentro del dominio capsule.corp

Cuando se quiere pedir acceso a un servicio en concreto, se debe especificar su SPN en la petición. Por ejemplo, cuando se pide un TGT al AS, el SPN sera siempre krbtgt/\[Domain Controller]

### Mensajes

Para finalizar, el AD da los siguientes nombres para los intercambios de mensajes:

| Mensaje de Kerberos | Descripción                                                 |
| ------------------- | ----------------------------------------------------------- |
| AS-REQ              | Petición de un Ticket-Granting Ticket (TGT) al servicio AS. |
| AS-REP              | Respuesta del servicio AS a una petición de TGT.            |
| TGS-REQ             | Petición de un Service Ticket (ST) al servicio TGS.         |
| TGS-REP             | Respuesta del servicio TGS a una petición de ST.            |
| AP-REQ              | Petición de autenticación mutua entre cliente y servidor.   |
| AP-REP              | Respuesta de autenticación mutua entre cliente y servidor.  |
| Error               | Mensaje de error en caso de fallo en la autenticación.      |

**Demo técnica interceptando los paquetes con Wireshark**: https://www.youtube.com/live/5uhk2PKkDdw?si=r7s3hQ8a70nzHOlv&t=3655

Nada mas poner las credenciales en tu ordenador, se hace una petición al DC para obtener un TGT para poder acceder a los servicios que ofrece tu ordenador! 

Cuando un usuario inicia sesión en un equipo del dominio, puede acceder a los servicios locales en ese equipo (como archivos compartidos, impresoras locales, etc.) utilizando el TGT obtenido del Controlador de Dominio (DC) durante el inicio de sesión. **No le hace falta un TS**. 

| Nota                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Los TGTs y los TSs son lo mismo: un ticket. Tienen prácticamente la misma estructura interna. Los TGTs te permiten autenticarte de manera local y los TS te permiten acceder a recursos remotos, pero en general se pueden ver como una misma cosa con propiedades diferentes. Se puede ver como que un TS esta construido sobre un TGT ya  que se les ha puesto algunas cosas para que sirva para utilizarlo para un servicio concreto. |
# (Ab)usando Kerberos

Existen varios tipos de ataques contra Kerberos. Hay dos grandes bloques:

| Acceso a credenciales      | Impersonacion de usuarios |
| -------------------------- | ------------------------- |
| Enumeración de usuarios    | Reutilizar tickets        |
| Enumeracion de contrasenas | Forjar tickets            |
| "Roasting"                 | Delegación de Kerberos    |

## Acceso a credenciales

### Enumeración de usuarios

La **enumeración de usuarios** en el contexto de Kerberos puede aprovecharse de cómo funciona el protocolo de autenticación. Cuando un cliente envía una solicitud de Ticket-Granting Ticket (**TGT**) al servicio AS (**AS-REQ**), incluye la identidad del usuario. Si el usuario es válido, el KDC responde con un TGT; si no es válido, el KDC devuelve un mensaje de error indicando que la identidad no es reconocida. Los atacantes pueden utilizar herramientas como Kerbrute para enviar solicitudes **AS-REQ** con una lista de posibles identidades y observar las respuestas del KDC. Si el KDC devuelve un mensaje de error, significa que la identidad no existe; de lo contrario, si no se recibe un mensaje de error, significa que la identidad es válida. Esto permite a los atacantes recopilar información sobre las identidades de usuario válidas en el dominio.

### Enumeración de contraseñas

En el contexto de Kerberos, la **enumeración de contraseñas** puede llevarse a cabo durante las solicitudes de pre-autenticación (**AS-REQ**). Los atacantes pueden intentar enviar solicitudes **AS-REQ** con contraseñas incorrectas para realizar un ataque de fuerza bruta y probar múltiples combinaciones de contraseñas hasta encontrar la correcta. Es importante tener en cuenta que esta técnica puede ser peligrosa ya que el Controlador de Dominio (DC) puede tener políticas de bloqueo de cuentas después de un cierto número de intentos fallidos. Por lo tanto, una técnica más segura es el "password spraying", que implica probar un pequeño número de contraseñas comunes contra múltiples cuentas de usuario. Es importante tener en cuenta que el KDC no genera el evento 4625, que es el típico evento que se genera si pones mal unas credenciales en un servicio, por ejemplo SSH. Sin embargo, hay un evento para este caso en concreto, que es el evento 4771 que se genera en caso de fallo en la pre-autenticación, este evento lo genera el KDC pero no está habilitado por defecto. Este tipo de ataques se pueden hacer con las herramienta Kerbrute. 

### "Roasting"

Los intercambios de Kerberos utilizan la clave simétrica (password) de un usuario o servicio para encriptar ciertas partes de los mensajes. 

Si se captura uno de estos mensajes escuchando las comunicaciones de la red o forzando a estos usuarios que emitan uno de estas peticiones, podemos intentar romper los hashes y recuperar las claves simétricas (passwords). Existen tres tipos de ataques de roasting:

- AS-REQroasting
- AS-REProasting
- TGS-REProasting (o Kerberoasting). 

Kerberos soporta diferentes cifrados. Por defecto van cifrados con AES256 con salt. Lo suyo es forzar tickets haciéndose pasar por un servicio que solo soporte algoritmos de cifrado mas débiles como RC4. 

#### AS-REQroasting

Las peticiones AS-REQ con datos de pre-autenticación contienen un timestamp cifrado con la password de un usuario. Si estamos en una red sin segmentación, podemos capturar estas peticiones y guardarlas. Una vez obtenidas, podemos coger esos timestamps e intentar crackearlos. Cifro el timestamp de la petición con una password de una wordlist y lo comparo: si coincide con alguna pues ya tengo una password encontrada. 

Este ataque se puede realizar con JohnTheRipper. El formato del hash para este ataque es la siguiente:

$krb5pa\$18\$\<Principal_Name\>\$\<REALM\>\$\<SALT\>\$\<CIPHER_BYTES\>
$krb5pa\$18\$vegeta\$CAPSULE.CORP\$CAPSULE.CORPVegeta\$\<CIPHER_BYTES\>

Para sacar los bytes cifrados de un paquete de wireshark: 
kerberos>as-req>padata>PA-ENC-TIMESTAMP>padata-value>cipher

| Nota                                                                                                                                                                                    |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Para saber el valor de la salt se debe obtener también la respuesta AS-REP. En Wireshark tal que: kerberos>as-req>padata>PA-ENCTYPE-INF02>padata-value>salt (para peticiones correctas) |

#### AS-REProasting

Estos mensajes contienen un TGT cifrado con la clave simétrica del servicio TGS y una clave de sesión que va a ir cifrada con la contraseña del usuario. Si se captura algún paquete AS-REP se puede intentar romper la clave de sesión ya que va cifrada con la password del usuario. 

Este ataque se puede realizar con JohnTheRipper. El formato del hash para este ataque es la siguiente:

$krb5asrep\$18\$\<SALT\>\$\<FIRST_BYTES\>\$\<LAST_12_BYTES\>

Para sacar los bytes cifrados de un paquete de wireshark: 
kerberos>as-rep>enc-part>cipher

Este tipo de ataque es especialmente interesante para cuentas de dominio que tengan activada la opción de no requerir la pre-autenticación de Kerberos. Esto quiere decir que para esa cuenta se puede enviar el AS-REQ sin credenciales y el servicio AS te va a devolver un TGT con la identidad de otro usuario (y cifrada con la clave del TGS) y una clave de sesión cifrada con la password de ese otro usuario. 

Esto quiere decir que para ese usuario puedes forzar obtener peticiones AS-REP sin tener que hacer replay de las peticiones AS-REQ. 

Al estar forzando la petición, podemos indicar que solo soportamos RC4 y por tanto el servicio AS nos tendrá que pasar la clave de sesión cifrada con la password de la victima pero con el algoritmo RC4. El formato del hash para este ataque es la siguiente:

$krb5asrep\$\<Principal_Name\>:\<FIRST__16_BYTES\>\$\<REMAINING_BYTES\>

#### TGS-REProasting (Kerberoasting)

Pedir un acceso a un servicio involucra enviar una TGS_REQ, eso significa que tenemos en nuestra posesión un TGT y, por lo tanto, somos capaces de pedir una ST para cualquier servicio (aunque no tengamos acceso). 

Además, sabemos que un ticket (ya sea el TGT o un ST) siempre va cifrado con la clave simétrica del servicio al que va dirigido. Sabiendo esto nos podemos plantear crackear las claves del servicio TGS o de cualquier otro servicio. 

| Nota                                                                                                                                                                                                                                            |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Hay una pega en todo esto y es que la clave del servicio TGS normalmente esta gestionada por el AD y suele ser una clave hipermegaenorme. Dicho esto, algún que otro admin puede cambiar la password del usuario krbtgt y ponerle una insegura. |
El objetivo del Kerberoasting es obtener STs y poder utilizarlos para crackear las contraseñas de un usuario de servicio. 

Algunos servicios los ofrecen cuentas de servidores o workstations. Las credenciales de estas cuentas las lleva el propio AD y, por lo tanto, suelen ser password bastante largas y aleatorias y además las van rotando. Por otro lado, hay algunos servicios (como Kerberos y la cuenta krbtgt) que necesitan que les crees una cuenta de servicio con un SPN registrado. Por ende, estas cuentas son llevadas por personas y, por lo tanto, pueden tener passwords inseguros. 

Además, al estar forzando la petición, podemos indicar que solo soportamos RC4 y por tanto el servicio TGS nos tendrá que pasar el TGS cifrado con la password de la cuenta de servicio pero con el algoritmo RC4. 

| Recuerda                                                                                                                                                                                                                                                                                                                                                                                   |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Obtener la clave de un servicio nos puede abrir muchos caminos pese a que ese servicio no este en ningún grupo de administración. Teniendo la clave del servicio se pueden forjar STs para ese servicio para cualquier identidad. Puedes hacerte pasar por cualquier persona en ese servicio, y esa persona puede tener ciertros privilegios dentro del servidor o en el servicio per se.  |

## Impersonation de Usuarios

### Reutilizar tickets

Se pueden hacer peticiones de TGT utilizando las siguientes credenciales:

- Username:Password
- Hash NTLM
- Key de Kerberos

Con este TGT se puede pedir tickets de servicio. 

#### Forjar tickets

Con la password de un servicio podemos descifrar, cambiar y volver a cifrar un Service Ticket que hayamos adquirido para ese servicio concreto. A este proceso se le llama forjar. 

**Golden Tickets**
Los Golden Tickets son tickets TGT forjados. Para ello se necesita la clave simétrica de krbtgt.
Se puede forjar un Golden Ticket con un usuario inexistente. Con la herramienta Ticketer de Impacket podemos forjar uno con el usuario que queramos y meterlo en Domain Admins (ya lo hace por defecto). 

**Silver Tickets**
Iguales que los Golden Tickets pero para cualquier otro servicio que no sea krbtgt

#### Delegación de Kerberos 

Esto se trata en otro video y por ende en otros apuntes.  