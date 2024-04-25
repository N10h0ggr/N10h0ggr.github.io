---
title: Process Argument Spoofing
date: 2024-04-21
categories:
  - malware
  - hiding
tags:
  - english
toc: "true"
---

The Import Address Table (IAT) holds crucial data about a PE file, including the functions utilized and the DLLs that export them. Such data is pivotal for signature-based detection of binaries. In this post, we'll delve into various techniques for obscuring our footprint.

## Introduction 

Security solutions such as AVs and EDRs are continuously analyzing the functions binaries import. Some functions such `CreateRemoteThread`, `OpenProcess`, `WriteProcessMemory`, etc. put the security solutions in alert mode, monitoring in more detail the process behavior. 

Okey, but how can those EDRs know what functions are the malware importing? One approach (but not the only one) is the Import Address Table (IAT). 

## The Import Address Table (IAT)

The **Import Address Table (IAT)** is a data structure used in the **Windows** operating system to facilitate dynamic linking of executable code. When a Windows program uses functions from **external libraries (DLLs)**, it doesn't directly call those functions by their memory addresses. Instead, it relies on dynamic linking, where the addresses of the functions are resolved at runtime.

The **IAT** is a table within the program's executable file that contains addresses of functions imported from DLLs. When the program is loaded into memory, the loader fills in this table with the actual addresses of the functions from the corresponding DLLs. This allows the program to call those functions without knowing their addresses in advance. Pretty useful right? 

So the one million dollar question; how can we import functions without getting flagged? One approach is create custom functions that perform the same actions as WinAPIs; easier said than done. 

## Creating GetProcAddress

The [GetProcAddress](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress) retrieves the address of an exported function (also known as a procedure) or variable from the specified dynamic-link library (DLL), then it searches that address through the exported functions inside the provided DLL. If the address is found, return that value, if not, the return value is NULL. Our objective is to create our alternative to this function. 

### The Export Table

The **Export Table** is a data structure **found within Dynamic Link Libraries (DLLs)** on the Windows operating system. It contains a list of functions and variables that the DLL makes available to other programs or DLLs. When a DLL is created, developers can specify which functions and variables should be accessible to other modules.

When another program or DLL wants to use a function or variable from a DLL, it can locate the Export Table within that DLL and find the necessary symbol along with its memory address. This allows the program to call the function or access the variable without needing to know its implementation details.

#### Export Table Structure

The Export Table serves as a directory of symbols exported by the DLL. This table follows the same structure as `IMAGE_EXPORT_DIRECTORY`. 

```c
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;          // Characteristics of the export directory
    DWORD   TimeDateStamp;            // Time and date the export data was created
    WORD    MajorVersion;             // Major version number
    WORD    MinorVersion;             // Minor version number
    DWORD   Name;                     // RVA (Relative Virtual Address) of the module name
    DWORD   Base;                     // Ordinal base value
    DWORD   NumberOfFunctions;        // Number of functions exported by the module
    DWORD   NumberOfNames;            // Number of function names
    DWORD   AddressOfFunctions;       // RVA of the array of function addresses
    DWORD   AddressOfNames;           // RVA of the array of function name pointers
    DWORD   AddressOfNameOrdinals;    // RVA of the array of function ordinals
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
```

The most relevant variables of this structure are:

1. `AddressOfFunctions`: This field contains the RVA (Relative Virtual Address) from the base of the image (DLL) to an array of RVAs. Each RVA in this array points to the address of a function within the DLL. The functions are typically stored in ascending order of their ordinals. To locate a specific function, you would use its ordinal to index into this array and retrieve its RVA, which you can then use to calculate the actual memory address of the function within the loaded DLL.
    
2. `AddressOfNames`: Similarly, this field contains the RVA to an array of RVAs. Each RVA in this array points to the name of a function exported by the DLL. The names are stored as null-terminated strings. To find the name of a specific function, you would use its ordinal to index into this array and retrieve the RVA of the function's name, which you can then dereference to access the actual function name.
    
3. `AddressOfNameOrdinals`: This field contains the RVA to an array of 16-bit ordinals. Each ordinal corresponds to the position of a function name in the `AddressOfNames` array and its associated address in the `AddressOfFunctions` array. To determine the ordinal of a function, you would use its name to search the `AddressOfNames` array and retrieve its index. This index corresponds to the ordinal stored in the `AddressOfNameOrdinals` array. Ordinals will be explained more in depth later. 

#### Accessing the Export Table

Within the structure of a **Windows Dynamic Link Library (DLL)**, the **Export Table** is encapsulated within what's known as the **IMAGE_EXPORT_DIRECTORY**. This directory serves as a repository for essential data regarding the functions and symbols that the DLL makes available for other programs to use.

Now, to understand where this **Export Table** resides within the **DLL file**, we need to navigate through its various headers. The starting point is the **IMAGE_DOS_HEADER**, which is the initial structure of any executable file in the DOS environment. This header contains basic information like the DOS stub and the file signature. Following the **DOS header**, we encounter the **IMAGE_NT_HEADERS**, which represent the **PE (Portable Executable) header** of the file. 

The [IMAGE_DOS_HEADER](https://0xrick.github.io/win-internals/pe3/) structure has the `e_lfanew` attribute, which is the file **offset** (in bytes) of the **PE header** (also known as the PE signature) relative to the beginning of the file. So to access to the **PE header** we need to know the **DOS header** address and add the offset indicated by the `e_lfanew`: 

```c
IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)hModule;
IMAGE_NT_HEADERS* pNtHeaders = (IMAGE_NT_HEADERS*)((DWORD)pDosHeader + pDosHeader->e_lfanew);
```

Within the **IMAGE_NT_HEADERS**, we find the **OptionalHeader**. The **OptionalHeader** section of the **IMAGE_NT_HEADERS** is a **IMAGE_NT_HEADERS**.

```c
typedef struct _IMAGE_NT_HEADERS {
  DWORD                   Signature;
  IMAGE_FILE_HEADER       FileHeader;
  IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

typedef struct _IMAGE_OPTIONAL_HEADER {
  WORD                 Magic;
  BYTE                 MajorLinkerVersion;
  BYTE                 MinorLinkerVersion;
  DWORD                SizeOfCode;
  DWORD                SizeOfInitializedData;
  DWORD                SizeOfUninitializedData;
  DWORD                AddressOfEntryPoint;
  DWORD                BaseOfCode;
  DWORD                BaseOfData;
  DWORD                ImageBase;
  DWORD                SectionAlignment;
  DWORD                FileAlignment;
  WORD                 MajorOperatingSystemVersion;
  WORD                 MinorOperatingSystemVersion;
  WORD                 MajorImageVersion;
  WORD                 MinorImageVersion;
  WORD                 MajorSubsystemVersion;
  WORD                 MinorSubsystemVersion;
  DWORD                Win32VersionValue;
  DWORD                SizeOfImage;
  DWORD                SizeOfHeaders;
  DWORD                CheckSum;
  WORD                 Subsystem;
  WORD                 DllCharacteristics;
  DWORD                SizeOfStackReserve;
  DWORD                SizeOfStackCommit;
  DWORD                SizeOfHeapReserve;
  DWORD                SizeOfHeapCommit;
  DWORD                LoaderFlags;
  DWORD                NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
```

 The **OptionalHeader** contains additional information about the executable or DLL, **including various optional data directories**. One of these directories is specifically designated for exporting functions, aptly named the **IMAGE_EXPORT_DIRECTORY**. 

Inside the **IMAGE_EXPORT_DIRECTORY**, you'll find details such as the names of exported functions, their memory addresses, and other relevant information needed for dynamic linking.

```c
typedef struct _IMAGE_DATA_DIRECTORY {
  DWORD VirtualAddress;
  DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
```

In the following code we access to the **DataDirectory** in the **Export Directory** point and save the **IMAGE_DATA_DIRECTORY** structure. After that, we access to the **VirtualAddress** parameter which holds the pointer to the **EXPORT_DIRECTORY** structure of the DLL:

```c
IMAGE_DATA_DIRECTORY exportDirectory = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(hModule + exportDirectory.VirtualAddress);
```

After obtaining a pointer to the **IMAGE_EXPORT_DIRECTORY** structure (see start of this section), it's possible to loop through the exported functions. 

The `NumberOfFunctions` member specifies the number of functions exported by `hModule`. As a result, the maximum iterations of the loop should be equivalent to `NumberOfFunctions`.  

```c
DWORD numberOfFunctions = pExportDirectory->NumberOfFunctions;
```

The next step is to build the search logic for the functions. This requires the use of `AddressOfFunctions`, `AddressOfNames`, and `AddressOfNameOrdinals`.

Since these elements are RVAs, the base address of the module, `hModule`, must be added to get the VA.

```c
DWORD* pAddressOfFunctions = (DWORD*)(hModule + pExportDirectory->AddressOfFunctions);
DWORD* pAddressOfNames = (DWORD*)(hModule + pExportDirectory->AddressOfNames);
WORD* pAddressOfNameOrdinals = (WORD*)(hModule + pExportDirectory->AddressOfNameOrdinals);
```

As mentioned before, `pAddressOfNameOrdinals` is the function's **ordinal**.

**What is an ordinal?**

An **ordinal** is a numerical value assigned to a function or procedure within a dynamic-link library (DLL). **Ordinals** are used as **identifiers for functions exported by the DLL**. When a DLL exports functions, it assigns each function a unique ordinal number, typically starting from 1 and incrementing by 1 for each subsequent function.

The ordinal number serves as an **alternative** way to reference exported functions within the DLL. Instead of using the function's name, you can use its ordinal to locate and access the function within the DLL's Export Table. This can be useful in scenarios where using the function's name may be inefficient or unnecessary.

For example, when dynamically linking to functions in a DLL, you may choose to use ordinals instead of names to reduce the size of the import table and improve performance. Additionally, using ordinals **can provide a level of obfuscation**, as it's **less intuitive** to identify functions solely by their ordinal numbers.

> **Note**
> 
> Ordinal value is used to identify a function's **address** rather than its name. The export table operates this way to handle cases where the function name is not available or is not unique.

That said, the following code snippet will print the ordinal value of each function in the function array of a specified module.

```c
for (DWORD i = 0; i < numberOfFunctions; i++){
	CHAR* pFunctionName	= (CHAR*)(hModule + pAddressOfNames[i]);
	WORD wFunctionOrdinal = pAddressOfNameOrdinals[i];
	printf("[ %0.4d ] NAME: %s -\t ORDINAL: %d\n", i, pFunctionName, wFunctionOrdinal);
}
```

## Full code

```c
#include <windows.h>
#include <stdio.h>

// Define the structure of the Export Directory
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;
    DWORD   AddressOfNames;
    DWORD   AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

int main() {
    // Load the DLL into memory
    HMODULE hModule = LoadLibrary(TEXT("YourDll.dll"));
    if (hModule == NULL) {
        printf("Failed to load DLL.\n");
        return 1;
    }

    // Get the base address of the DLL
    DWORD dwBaseAddress = (DWORD)hModule;

    // Locate the Export Directory
    IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)hModule;
    IMAGE_NT_HEADERS* pNtHeaders = (IMAGE_NT_HEADERS*)((DWORD)pDosHeader + pDosHeader->e_lfanew);
    IMAGE_DATA_DIRECTORY exportDirectory = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (exportDirectory.VirtualAddress == 0 || exportDirectory.Size == 0) {
        printf("Export Directory not found.\n");
        return 1;
    }

    // Access the Export Directory
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(dwBaseAddress + exportDirectory.VirtualAddress);

    // Access Exported Function Information
    DWORD* pAddressOfFunctions = (DWORD*)(dwBaseAddress + pExportDirectory->AddressOfFunctions);
    DWORD* pAddressOfNames = (DWORD*)(dwBaseAddress + pExportDirectory->AddressOfNames);
    WORD* pAddressOfNameOrdinals = (WORD*)(dwBaseAddress + pExportDirectory->AddressOfNameOrdinals);
    DWORD numberOfFunctions = pExportDirectory->NumberOfFunctions;

    // Print the exported function names
    printf("Exported Functions:\n");
    for (DWORD i = 0; i < numberOfFunctions; i++) {
        printf("%s\n", (char*)(dwBaseAddress + pAddressOfNames[i]));
    }

    // Free the loaded DLL
    FreeLibrary(hModule);

    return 0;
}
```