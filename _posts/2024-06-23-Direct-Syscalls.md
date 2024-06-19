---
title: Direct Syscalls
date: 2024-06-23
categories:
  - malware
tags:
  - english
toc: "true"
---

### SysWhispers
Tiene una tabla precomputada en assembly donde mapea una function a una syscall concreta para cada version de sistema operativo. 
### SysWhispers2/FreshyCalls
Consulta la tabla de todas las funciones que exporta `ntdll.dll`. De ahi saca los nombres, ordinales y direcciones virtuales (VA) de cada funcion. Se carga las que empiecen por zw. Luego ordena por direcciones virtuales (de menor a mayor): La primera de la lista tiene asignada como syscall el numero 1, la segunda el numero 2, etc.
### SysWhispers3
Ni puta idea porque utiliza indirect syscall y todavia no lo he visto. 
### Hells Gate 
Se crea un tabla con el hash del nombre de las funciones que quiere buscar. Luego exporta la tabla de todas las funciones que exporta `ntdll.dll`. Sin ordenar ni nada, se pone a recorrer la lista y a ver si algún hash coincide. Si alguno coincide, se guarda la dirección.

Una vez tiene las direcciones de las funciones, comprueba que las primeras instrucciones no sean las instrucciones`0x4f`, `0x05` (`syscall`) o `0xc3` (`ret`). Después de eso, vuelve a comprobar de golpe y byte por byte las instrucciones de la función en busca de las instrucciones `0x4c, 0x8b, 0xd1, 0xb8`(`mov r10, rcx` y `mov eax, ssn`). 

Si hay alguna instrucción de mas que no debería estar (por ejemplo un hook), la función falla.
### Halos Gate
Igual que Hells Gate pero este comprueba que no haya hooks puestos. Esto lo hace buscando la instrucción `e9` (`jmp`) dentro de la función. Si la encuentra, salta a las funciones adyacentes. 

Consigue saltar a las funciones adyacentes poniendo un multiplicador al offset que se utiliza junto la dirección base de la funcion. 

Si todas las funciones esta hookeadas estas jodido. 
### Tartarus Gate 
Igual que Halos Gate pero la comprobación del `jmp` la hace también después de las instrucciones `mov r10, rcx`. 