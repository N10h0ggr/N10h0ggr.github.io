---
title: API Hooking
date: 2024-06-16
categories:
  - malware
tags:
  - english
toc: "true"
---
In this post, we'll explore API hooking, a technique used to intercept and be able to modify function calls in software. We'll delve into the different types of function hooking, focusing on Inline Hooks and Trampolines, and provide practical examples in C and Rust to illustrate how these hooks can be implemented. 
## What is API Hooking?

API Hooking is a technique used to intercept and modify calls to system or library functions. This is typically achieved by redirecting the flow of execution from the original function to a custom function. By doing so, developers can monitor, modify, or extend the behavior of these functions without modifying the original code.

API hooking is widely used by security solutions to inspect commonly abused functions more thoroughly. It is utilized for **malware analysis**, **debugging** purposes, and to **add extended functionalities**.

From an attacker's perspective, API hooking can be used for the following purposes:

1. **Gather sensitive information or data** (e.g., credentials).
2. **Modify or intercept function calls for malicious purposes**.
3. **Bypass security measures** by altering how the operating system or a program behaves (e.g., AMSI, ETW).
## Types of Function Hooking

Function hooking is a powerful technique used to alter the behavior of software by intercepting function calls, messages, or events. Various methods can achieve this, each with its own advantages and use cases:

- **Inline Hooks**: Directly modifies the machine code of the target function to redirect execution to a different function.
- **Trampolines**: Inserts a jump to a detour function while preserving the original function’s prologue, allowing execution to return after the hook.
- **Hardware Breakpoints**: Utilizes CPU hardware features to break execution at specific memory addresses, often used for debugging.
- **Software Breakpoints**: Inserts a special breakpoint instruction into the target code, typically used for debugging and analysis.
- **Virtual Table Hooks**: Alters the function pointers in a class’s virtual table (vtable) to redirect virtual function calls.
- **Import Address Table Hooks**: Modifies entries in a module’s Import Address Table (IAT) to reroute API calls to different implementations.
- **Export Address Table Hooks**: Changes the addresses in the Export Address Table (EAT) of a DLL to redirect exported function calls.

For this post, we'll focus on the first two methods, Inline Hooks and Trampolines, as they are fundamental techniques that form the basis for many advanced hooking strategies. Understanding these will provide a solid foundation for exploring more complex methods in future posts.
### Trampolines

A trampoline is a small piece of code used to change the execution flow of a program by redirecting it to a different address within the process's memory. This code is placed at the start of a target function, effectively intercepting calls to that function. When the target function is called, the trampoline code runs first, changing the execution flow to the desired function address. This redirection allows a different function to be executed in place of the original one, thus altering the program's behavior.
![Trampoline.png](assets/img/posts/malware/hooking/Inline-hooking.png)
_Trampoline Functions_
### Inline Hooking

Inline hooking is another method of API hooking, similar to trampoline-based hooking. The key difference is that inline hooks allow the execution to return to the original function, enabling it to continue running normally. Although this technique is more complex to implement and can be harder to maintain, it offers greater efficiency.
![Inline-hooking.png](assets/img/posts/malware/hooking/Inline-hooking.png)
_Inline Hooking_

## Implementation

API hooking can be implemented in various ways. One common method is through open-source libraries like Microsoft's Detours or MinHook. Another, though more restricted, method is using specific Windows APIs designed for API hooking.

To create hooks, these libraries use a type of atomic operation called transactions. Transactions are widely used for critical operations due to the stability they offer.

### Transactions

A transaction represents a series of operations that must be executed as a single, indivisible unit to maintain data integrity and consistency. Transactions adhere to the **ACID** properties: **Atomicity** (all or nothing), **Consistency** (maintains data integrity), **Isolation** (operations appear to occur in isolation from other transactions), and **Durability** (changes are permanent once committed).

In the API Hooking context, transactions are used to group a series of hook operations into a single atomic action. This ensures that all hooks are applied consistently and without partial updates, which could lead to unstable or inconsistent states.

The full Hook Transaction process covers the following actions:

1. **Begin Transaction**: Starts a new transaction.
2. **Update Thread**: Specifies which threads should be updated with the new hooks.
3. **Attach/Detach Hooks**: Adds or removes hooks as part of the transaction. This won't be committed until the next step is called.
4. **Commit Transaction**: Applies all changes made during the transaction.

If any of these steps go wrong, the full process will roll back.

### The Infinite Loop Problem

When the code calls a hooked function, it does not expect to be hooked. It might expect a normal return value. How do we, as the creators of the hook function, return a valid value? The naive solution is to call the original function and return whatever it returns. This is wrong because calling the original function will lead to an infinite loop.

**How do we solve that?**

There are two main approaches:

1. **Saving a pointer to the original function prior to hooking it**: This pointer can be stored in a global variable and be invoked later.
2. **Calling a different _unhooked_ function that has the same functionality as the hooked function**: For example, `MessageBoxA` and `MessageBoxW`, `VirtualAlloc` and `VirtualAllocEx`.

Since the second solution is trivial, we will provide an example of solving it with the first approach in the code examples.
### Code Examples

To help you understand how to implement API hooking, here are some practical examples using both the Detours library in C and custom shellcode in Rust.
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

``` Rust
use std::{mem, ptr, slice};  
use std::ffi::{c_void, CStr};  
use std::mem::size_of;  
  
use windows::core::{PCSTR, s, w};  
use windows::Win32::Foundation::HWND;  
use windows::Win32::System::Memory::{PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, VirtualProtect};  
use windows::Win32::UI::WindowsAndMessaging::{MB_ICONINFORMATION, MB_ICONQUESTION, MB_ICONWARNING, MB_OK, MESSAGEBOX_RESULT, MESSAGEBOX_STYLE, MessageBoxA, MessageBoxW};  
  
#[cfg(target_pointer_width = "64")]  
const TRAMPOLINE_SIZE: usize = 13;  
  
#[cfg(target_pointer_width = "32")]  
const TRAMPOLINE_SIZE: usize = 7;  
  
struct Hook {  
    p_function_to_hook: *const u8,  
    p_function_to_run: *const u8,  
    v_original_bytes: Vec<u8>,  
    dw_old_protection: *mut PAGE_PROTECTION_FLAGS,  
}  
  
impl Hook {  
    unsafe fn new(p_function_to_hook: *const u8, p_function_to_run: *const u8) -> Option<Self> {  
        if p_function_to_hook.is_null() || p_function_to_run.is_null() {  
            return None;  
        }  
  
        let mut hook = Self {  
            p_function_to_hook,  
            p_function_to_run,  
            v_original_bytes: Vec::new(),  
            dw_old_protection: &mut PAGE_PROTECTION_FLAGS::default(),  
        };  
  
        hook.v_original_bytes = slice::from_raw_parts(p_function_to_hook, TRAMPOLINE_SIZE).to_vec();  
  
        // Changing the protection to RWX to be able to modify the bytes  
        // Saving the old protection to the struct (to re-place it at cleanup)        VirtualProtect(p_function_to_hook as *const c_void, TRAMPOLINE_SIZE, PAGE_EXECUTE_READWRITE, hook.dw_old_protection)  
            .unwrap_or_else(|e| {  
                panic!("[!] Create Hook: VirtualProtect Failed With Error: {e}");  
            });  
  
        Some(hook)  
    }  
}  
  
fn install_hook(hook: &Hook) {  
    #[cfg(target_pointer_width = "64")]  
        let trampoline = prepare_x64_trampoline(&hook);  
    #[cfg(target_pointer_width = "32")]  
        let trampoline = prepare_x32_trampoline(&hook);  
    unsafe {ptr::copy_nonoverlapping(  
        trampoline.as_ptr(),                // Source pointer  
        hook.p_function_to_hook as *mut u8, // Destination pointer  
        trampoline.len()                    // Number of bytes to copy  
    );}  
}  
  
fn prepare_x64_trampoline(hook: &Hook) -> Vec<u8>{  
    let mut trampoline: Vec<u8> =  vec![  
        0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r10, pFunctionToRun  
        0x41, 0xFF, 0xE2                                            // jmp r10  
    ];  
  
    let sliced_p_function_to_hook: [u8; 8] = unsafe { mem::transmute(hook.p_function_to_run as u64) };  
    trampoline.splice(2..10, sliced_p_function_to_hook.iter().cloned());  
    trampoline  
}  
  
fn prepare_x32_trampoline(hook: &Hook) -> Vec<u8>{  
    let mut trampoline: Vec<u8> = vec![  
        0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, pFunctionToRun  
        0xFF, 0xE0                    // jmp eax  
    ];  
    unsafe {  
        let source = slice::from_raw_parts(hook.p_function_to_hook, size_of::<usize>());  
        trampoline[1..].copy_from_slice(source);  
    }  
    trampoline  
}  
  
fn remove_hook(mut hook: Hook) {  
    // memcpy: copying the original bytes over  
    unsafe {ptr::copy_nonoverlapping(  
        hook.v_original_bytes.as_ptr(),     // Source pointer  
        hook.p_function_to_hook as *mut u8, // Destination pointer  
        TRAMPOLINE_SIZE,        // Number of bytes to copy  
    );  
        // cleaning up our buffer  
        hook.v_original_bytes.clear();  
        // setting the old memory protection back  
        VirtualProtect(hook.p_function_to_hook as *const c_void, TRAMPOLINE_SIZE, PAGE_EXECUTE_READWRITE, hook.dw_old_protection)  
            .unwrap_or_else(|e| {  
                panic!("[!] Remove Hook: VirtualProtect Failed With Error: {e}");  
            });  
    }  
    hook.p_function_to_hook = ptr::null();  
    hook.p_function_to_run = ptr::null();  
    hook.dw_old_protection = &mut PAGE_PROTECTION_FLAGS::default();  
}  
  
fn my_message_box_a(hwnd: HWND, p_text: PCSTR, p_caption: PCSTR, u_type: MESSAGEBOX_STYLE) -> MESSAGEBOX_RESULT {  
    // Print original parameters  
    println!("[+] Original Parameters:");  
    unsafe {  
        let s_text = CStr::from_ptr(p_text.0 as *const i8).to_str().expect("Invalid UTF-8 string");  
        let s_caption = CStr::from_ptr(p_caption.0 as *const i8).to_str().expect("Invalid UTF-8 string");  
        println!("\t - p_text   : {}", s_text);  
        println!("\t - p_caption: {}", s_caption);  
    }  
  
    // Call MessageBoxW with modified parameters  
    let new_text = w!("Malware Development Is Cool");  
    let new_caption = w!("Hooked MsgBox");  
    unsafe { MessageBoxW(hwnd, new_text, new_caption, u_type) }  
}  
  
fn main() {  
    let text = s!("What Do You Think About Malware Development?");  
    let caption = s!("Question MsgBox");  
    unsafe { MessageBoxA(HWND(0), text, caption, MB_OK | MB_ICONQUESTION); }  
  
    let function_to_hook= MessageBoxA::<HWND, PCSTR, PCSTR> as *const u8;  
    let function_to_run= my_message_box_a as *const u8;  
  
    let hook = unsafe { Hook::new(function_to_hook, function_to_run) }  
        .expect("[!] Failed to initialize hook structure.");  
  
    println!("[i] Installing The Hook ... ");  
    install_hook(&hook);  
    println!("[+] DONE");  
  
    let text = s!("Malware Development Is Bad");  
    let caption = s!("Response MsgBox");  
    unsafe { MessageBoxA(HWND(0), text, caption, MB_OK | MB_ICONWARNING); }  
  
    println!("[i] Removing The Hook ... ");  
    remove_hook(hook);  
    println!("[+] DONE");  
  
    let text = s!("Normal MsgBox Again");  
    let caption = s!("Final MsgBox");  
    unsafe { MessageBoxA(HWND(0), text, caption, MB_OK | MB_ICONINFORMATION); }  
}
```

## Results

`MessageBoxA` is executed without problems, as expected:
![hooking_1.png](assets/img/posts/malware/hooking/hooking_1.png)
_Run MessageBoxA before hooking_

After clicking the OK button the trampoline hooking shellcode is installed in `MessageBoxA` function:
![hooking_2.png](assets/img/posts/malware/hooking/hooking_2.png)
_MessageBoxA after hook_

Once installed, `MessageBoxA` is called again. The execution flow is changed and our function is executed instead:
![hooking_3.png](assets/img/posts/malware/hooking/hooking_3.png)
_Hooked function execution_

Now that our function has finished, is time for cleanup. Trampoline shellcode is removed from `MessageBoxA` function: 
![hooking_4.png](assets/img/posts/malware/hooking/hooking_4.png)
_Hook cleanup_

To be sure the hook has been removed, `MessageBoxA` is called one more time: 
![hooking_5.png](assets/img/posts/malware/hooking/hooking_5.png)
_MessageBoxA execution after cleanup_
## References: 
- [Function Hooking: Trampolines & Detours](https://www.codereversing.com/archives/593)
- [Maldev Academy](https://maldevacademy.com/)