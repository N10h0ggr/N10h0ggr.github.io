---
title: API Hooking
date: 2024-06-16
categories:
  - malware
tags:
  - english
toc: "true"
---
## What is API Hooking?
API Hooking is a technique used to intercept and alter calls to system or library functions. This is typically achieved by redirecting the flow of execution from the original function to a custom function. By doing so, developers can monitor, modify, or extend the behavior of these functions without modifying the original code.

API hooking is widely used by security solutions to allow them to inspect commonly abused functions more thoroughly. It is used for **malware analysis**, **debugging** purposes and to **add extended functionalities** too. 

Nevertheless, from an attackers perspective, API hooking can be used with the following purposes:

1. Gather sensitive information or data (e.g. credentials).
2. Modify or intercept function calls for malicious purposes.
3. Bypass security measures by altering how the operating system or a program behaves (e.g. AMSI, ETW).

## Types Function Hooking

==The there are many different ways to achieve Function Hooking:==

- ==Inline Hooks==
- ==Trampolines==
- ==Hardware Breakpoints==
- ==Software Breakpoints==
- ==Virtual Table Hooks==
- ==Import Address Table Hooks== 
- ==Export Address Table Hooks==

==To not be very extense we will talk about the first two==
### Trampolines
A trampoline is a small piece of code used to change the execution flow of a program by redirecting it to a different address within the process's memory. This code is placed at the start of a target function, effectively intercepting calls to that function. 

When the target function is called, the trampoline code runs first, changing the execution flow into the desired function address. This redirection allows a different function to be executed in place of the original one, thus altering the program's behavior.
![[Pasted image 20240529122856.png]]
_Trampoline Functions_
### Inline Hooking
Inline hooking is another method of API hooking, similar to trampoline-based hooking. The key difference is that inline hooks allow the execution to return to the original function, enabling it to continue running normally. Although this technique is more complex to implement and can be harder to maintain, it offers greater efficiency.

![[Pasted image 20240529124310.png]]
_Inline Hooking_

## Implementation
API hooking can be implemented in various ways. One common method is through open-source libraries like Microsoft's Detours or Minhook. Another, though more restricted, method is using specific Windows APIs designed for API hooking.

To be able to create hooks, those libraries use a type of atomic operation called Transactions. This transactions are widely use for critical operations due the stability they offer. 
### Transactions
A transaction represents a series of operations that must be executed as a single, indivisible unit to maintain data integrity and consistency. Transactions adhere to the **ACID** properties: **Atomicity** (all or nothing), **Consistency** (maintains data integrity), **Isolation** (operations appear to occur in isolation from other transactions), and **Durability** (changes are permanent once committed). 

Transactions begin with a specific operation, proceed with one or more intermediate steps, and conclude with a commit or rollback operation to confirm or discard the changes made during the transaction.

In the API Hooking context, transactions are used to group a series of hook operations into a single atomic action. This ensures that all hooks are applied consistently and without partial updates, which could lead to unstable or inconsistent states. 

The full Hook Transaction process covers the following actions:

1. **Begin Transaction**: Starts a new transaction.
2. **Update Thread**: Specifies which threads should be updated with the new hooks.
3. **Attach/Detach Hooks**: Adds or removes hooks as part of the transaction. This won't be committed until next step is called. 
4. **Commit Transaction**: Applies all changes made during the transaction.

If any of these steps go wrong, the full process will rollback. 

### The Infinite Loop Problem
When the code is calling a hooked function it does not expect to be hooked, right? So it might expect a normal return value. How do we, as the creators of the hook function, return a valid value? Easy, call the original function and return whatever it returns. Wrong. As the original function is hooked we will end in an infinite loop. 

**How do we solve that?** 
There are two main approaches: 
1. Saving a pointer to the original function prior to hooking it. This pointer can be stored in a global variable and be invoked later
2. Calling a different _unhooked_ function that has the same functionality as the hooked function. For example `MessageBoxA` and `MessageBoxW`, `VirtualAlloc` and `VirtualAllocEx`.

As the second solution is very trivial we will provide an example of how to solve it with the first approach in the code examples. 
### Code Examples

#### API Hooking using Detours Library with C
```c
#include <windows.h>
#include "detours.h"

static int (WINAPI *Real_MessageBoxA)(HWND, LPCSTR, LPCSTR, UINT) = MessageBoxA;

int WINAPI Hooked_MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    return Real_MessageBoxA(hWnd, "Hooked Text", lpCaption, uType);
}

void AttachHooks() {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)Real_MessageBoxA, Hooked_MessageBoxA);
    DetourTransactionCommit();
}

void DetachHooks() {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)Real_MessageBoxA, Hooked_MessageBoxA);
    DetourTransactionCommit();
}

int main() {
    AttachHooks();
    MessageBoxA(NULL, "Original Text", "Title", MB_OK);
    DetachHooks();
    return 0;
}
```

#### API Hooking using Minhook Library with C

```c
#include <windows.h>
#include "MinHook.h"

typedef int (WINAPI *MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);
MessageBoxA_t Real_MessageBoxA = NULL;

int WINAPI Hooked_MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    return Real_MessageBoxA(hWnd, "Hooked Text", lpCaption, uType);
}

void AttachHooks() {
    MH_Initialize();
    MH_CreateHook(&MessageBoxA, &Hooked_MessageBoxA, (LPVOID*)&Real_MessageBoxA);
    MH_EnableHook(&MessageBoxA);
}

void DetachHooks() {
    MH_DisableHook(&MessageBoxA);
    MH_Uninitialize();
}

int main() {
    AttachHooks();
    MessageBoxA(NULL, "Original Text", "Title", MB_OK);
    DetachHooks();
    return 0;
}
```

#### Trampoline API Hooking using Custom Shellcode with Rust

#### API Hooking using SetWindowsHookEx WinAPI call with Rust

## References: 
- [Function Hooking: Trampolines & Detours](https://www.codereversing.com/archives/593)