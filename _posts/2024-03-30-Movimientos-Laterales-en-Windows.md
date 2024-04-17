---
title: Movimientos Laterales en Windows
date: 2024-03-30
tags:
  - spanish
toc: "true"
---

Este post o apuntes explicarán de manera más o menos extensa como ejecutar movimientos laterales entre usuarios o entre sistemas. 

# Autenticación

Principalmente existen dos formas de autenticarse: NTLM y Kerberos, aunque también existen otros métodos.

Estas autenticaciones se pueden clasificar en dos grupos:

- **Autenticación activa o física**: El usuario pone sus credenciales directamente en el host donde quiere iniciar sesión. Este tipo de autenticación no requiere de ningún privilegio en especial. 
- **Autenticación pasiva o remota**: El usuario inicia sesión desde otro dispositivo, ya sea a través de SSH, RDP o cualquier otro tipo de autenticación que no supongo estar físicamente en frente de la máquina. Este tipo de autenticación requiere de algún privilegio en especial en su identidad. 

Ojo, esto aplica tanto para autenticaciones locales (autenticación vía SAM) como para autenticaciones por AD (vía NTDS). Iniciar sesión en un servidor remoto como .\user también requiere de privilegios que no vienen dados por defecto. Iniciar sesión como Corp\DomainUser1 físicamente desde una workstation no requiere de privilegios especiales, es posible con la cuenta por defecto. Otra cosa es que a esa workstation se le haya aplicado una whitelist. 

Paquetes de autenticación 
Como hemos mencionado antes existen dos tipos de autenticaciones predominantes. Cada una de estas utiliza una DLL distinta y un flujo propio. 

Autenticación local por Msv1_0 (NTLM):

1.	El usuario envía una petición al SAM del hostA (pe. hostA\\attl4s)
2.	El hostA le envía un challenge
3.	El usuario firma ese challenge con su hash NTLM 
4.	El sistema confirma la firma a través de SAM.

Para AD también se puede utilizar y seguramente se utilice NTML junto con Kerberos. Para la explicación de Kerberos hay otra hoja de apuntes. 

Nota: Se pueden añadir grupos de AD y usuarios concretos de AD como administradores locales de un sistema concreto.

Nota: El grupo de Domain Admins siempre está como administradores locales de todas las máquinas por una o dos políticas que vienen activadas por defecto en el DC. 

El flujo de autenticación de puede resumir de la siguiente manera:

1.	El usuario se autentica en un sistema, ya sea de manera física o remota
2.	El paquete de autenticación (ya sea Kerberos, NTLM u otro) crea una Logon Session; junta el ID de esa Logon Session con la información de seguridad (identificadores, privilegios, etc.) y se lo pasa al Local Security Authorization (LSASs).
3.	LSAS crea un Token

# Logon Sessions
Una logon session es un ente que se crea cuando una autenticación es correcta. 

IMPORTANTE: Todas las credenciales que se almacenan en memoria están SIEMPRE vinculadas a una Logon Session.

Existen dos tipos de logon sessions: 
- Interactivas (que no van por la red)
- No interactivas (remotas) 

Las logon sessions son distintas dependiendo de los niveles de privilegios que tenga el usuario (también llamados niveles de integridad). Los procesos de integridad medias son aquellos procesos que corren con privilegios normales de usuario y los de integridad alta son todos aquellos procesos que corren como administrador. Esta diferenciación obliga a crear dos logon session distintas para un mismo usuario. 

Nota: Como Kerberos no trabaja con IPs, cuando accedes a una carpeta compartida de sistema (tal que \\10.10.10.10\C$) se crea una logon session no interactiva autenticada por NTLM. Ten en cuenta que esa logon session se crea en el sistema 10.10.10.10. Si en vez de utilizar la ip utilizas el hostname o SPN, la autenticación será por Kerberos.

Importante: Las logon sessions interactivas se guardan en memoria en el proceso lsass.exe para implementar el SSO.

La autenticación para sesiones no interactivas funcionan de tal manera que el usuario tiene que demostrar que tiene esas credenciales sin enviarlas a través de la red. De este modo las credenciales no están guardadas en memoria. A no ser que se utilice la delegación de Kerberos o opciones específicas para ciertos tipos de autenticación.

Importante: tener acceso no interactivo a un sistema no implica que podamos tener acceso a todos los recursos de ese sistema. Me explico: conseguimos una shell remota como administrador de sistema en host01. Al ser una sesión no interactiva, las credenciales no se guardan en memoria. Al no guardarse las credenciales en memoria, no está implementado el SSO, por lo que para cualquier acción sobre un host remoto que requiera autenticación (por ejemplo listar una carpeta compartida) tendremos que proporcionar las credenciales. Si estas credenciales estuvieran en memoria no tendríamos que especificarlas. 

El LSA es el encargado de crear tokens pra poder acceder a los recursos y aplicaciones de manera local. Cada token está ligado a una logon session.

Process/thread tiene un token Token que referencia a una logon sessions que a su vez pueden tener (o no) credenciales

# Access tokens

Los access tokens son unas estructuras de datos que contienen información sobre la identidad y los privilegios asociados a una cuenta de usuario. 

Cada proceso ejecutado en nombre de un usuario tiene una copia del token. Un usuario puede tener varios tokens, uno para cada "contexto" de ejecución. 

Los access token sirven para que Windows pueda implementar controles de accesos. Dentro de los descriptores de seguridad de Windows (Object Security Descriptors) de un objeto concreto (p.e. un fichero) hay un atributo que es la Discretionary Access Control List (DACL) que contiene una serie de reglas que definen quien tiene acceso y quien no a ese recurso en especifico. Los access token sirven para que los procesos o hilos puedan presentar un identificador al sistema operativo. El SO entonces mira si el User SID o los grupos se encuentran en la DACL del recurso u objeto y que permisos tiene sobre él.  

## Tipos de tokens

Se pueden diferenciar dos tipos de tokens:
### Primary Tokens (Tokens de procesos)
Cada proceso tiene un primary token asociado. Por defecto, hereda el token de su proceso padre. 

### Impersonation Tokens (Tokens de hilo)
Permiten que los hilos puedan corren en un contexto de seguridad diferente al proceso del que proviene. Normalmente se utilizan en escenarios de cliente/servidor (cuentas de servicio). 

Por ejemplo, una base de datos suele correr sobre una cuenta de servicio. El proceso de la BBDD tiene asociado un hilo principal que hereda su Primary Token. Ahora bien, cuando un usuario (p.e. User B) se conecta a la base de datos, se genera un nuevo hilo, y ese hilo se crea con un Impersonation Token que representa al User B, suplantandolo. De esta forma cuando el User B intente acceder a ciertas tablas de la BBDD se podrán aplicar los controles de acceso pertinentes. 

Por norma general, las cuentas de servicio vienen con el privilegio SeImpersonatePrivilege y SeAssignePrimaryPrivilege, para que cuando un usuario se conecta a un servicio este pueda crear un Access Token suplantándolo. Esto es lo que abusa la vulnerabilidad RottenPottato.

Dentro de los impersonation tokens existen cuatro niveles dependiendo distintos dependiendo de la información que haya dentro del token. A nosotros solo nos interesan los tokens que suplantan al usuario de manera completa (también llamados los Delegation Tokens).

Los Delegation Tokens hacen referencia a una Logon Session interactiva, con lo que tienen credenciales en memoria y que por lo tanto se pueden utilizar para acceder a recursos remotos. 

# Imitando usuarios

Imitar o impersonar es la habilidad de un hilo de poder ejecutarse un contexto de seguridad diferente del contexto de seguridad del proceso al que pertenece.

En este punto, desde la perspectiva de un atacante nos podemos preguntar tres preguntas.
## Tengo passwords?

Imaginemos que hemos encontrado una password en un fichero compartido. En este punto se pueden hacer varias cosas. 

La primera es el utilizar runas.exe. Runas.exe es útil para hacer un movimientos laterales ejecutando comandos como otros usuarios. Si entras en una maquina como el usuario Pepe, y tienes las credenciales de Jesus, puedes ejecutar comandos como Jesus. Esto es valido tanto si Jesus es un usuario local del sistema o es un usuario de dominio, lo importante es que tenga acceso al sistema. 

Por defecto runas ejecuta los comandos de manera local. Para poder ejecutar commandos de manera remota, es necesario utilizar el flag /netonly. Por ejemplo, mira este comando:

``` 
runas /user:capsule.corp\vegeta /netonly cmd 
```

Este comando nos pedirá las credenciales del usuario de dominio vegeta y abrirá una cmd. Este cmd esta abierto de manera local, pero con la peculiaridad de que intentemos interactuar con un recurso o sistema remoto, utilizara las credenciales que le hemos proporcionado anteriormente para autenticarse. Es importante destacar que nuestro sistema no va a comprobar si las credenciales son correctas, eso le pertoca al sistema remoto. Por lo tanto, la logon session que se crea al estar utilizando la flag /netonly no va a concordar con el access token del proceso runas

Al ejecutar runas con esta flag, windows crea una nueva logon session con las credenciales que le hemos indicado. Acto seguido clona el access token del proceso que ha ejecutado runas y lo modifica para que haga referencia al nuevo logon session. Finalmente crea un nuevo proceso (en este caso el cmd) y le asigna ese access token. 

Runas pide las credenciales de manera interactiva, lo que lo hace imposible de utilizar a través de una shell inversa. Además, es posible que se registre el uso de runaes en los logs y eventos del sistema. 

La gran mayoría de frameworks C2 tienen su propia implementación de runas a través de la Win32 API. 

Este ejecutable crea un access token similar al que se crea con un logon interactivo, es decir, que guarda las credenciales en memoria para implementar el SSO. 

## Y si tengo un HASH?

### Pass the hash en Windows
Los pasos son prácticamente los mismos que utiliza runas:

1. Crea una nueva logon session
2. Modifica el hash de esa nueva logon session (hacen falta permisos de admin)
3. Copia el token original y lo hace referenciar a la nueva logon session. 
4. Usa ese token

Es como runas /netonly pero con el hash en vez de con la password.

En un procedimiento normal, un usuario podría sus credenciales y LSASS crearía el hash NTLM para garantizar el acceso al host. Utilizando Pass the Hash lo que haces es inyectar ese hash directamente a LSASS. 

Nota: mimikatz implementa tanto pass the hash como over-pass the hash: un vez se ha escrito el hash NTLM en LSASS, este se aprovecha de ello para que Windows pida tickets TGS. 
### Pass the ticket
Es lo mismo que pass the hash pero con tickets TGT. La librería de Kerberos nos permite importar tickets sin la necesidad de ser administradores. 

Importante: este tipos de ataques se pueden identificar si se encuentran logon sessions que contienen tokens o tickets que no son del mismo propietario que dicha logon session. 
#### ASK-TGT/TGS
Genera el tráfico legítimo de Kerberos sin la necesidad de que Windows intervenga, lo que no es necesario ser administrador. 

## Que pasa con los tokens?
Al final todos los pasos anteriores son necesarios si no tenemos ya un token que nos interese. Un proceso que nos pueda interesar puede ser cualquier proceso con sesión interactiva de un administrador de dominio. Recuerda que para que el token tenga las credenciales en memoria, debe estar asociado a una logon session interactiva. 

Las acciones de manipular tokens requieren permisos de administrador local. 
### Token impersonation/theft 
Básicamente consiste en duplicar un token (que nos interese) y que haga referencia a una logon session con credenciales. Luego este token se lo asignamos a un nuevo proceso o a un thread de un proceso que nos interese. Esto se puede conseguir a través de la Win32 API. 

### Inyectar tokens con contexto
Esta segunda técnica consiste en inyectarte en el cotexto donde está el token que te interesa. Consiste en inyectar payload (que puede ser una DLL) en el proceso al que está asignado el token que nos interesa. También puede ser el process hollowing, etc.