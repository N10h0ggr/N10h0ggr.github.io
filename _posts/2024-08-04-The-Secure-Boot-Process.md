---
title: The Secure Boot Process
date: 2024-08-04
categories:
  - Malware Analysis
  - Theory
tags:
  - Bootkits-and-Rootkits
toc: "true"
---
The evolution of malware, particularly rootkits and bootkits, represents a significant threat to modern computing systems. "Rootkits and Bootkits: Reversing Modern Malware and Next Generation Threats" by Alex Matrosov, Eugene Rodionov, and Sergey Bratus offers a deep dive into these sophisticated forms of malware. This blog post aims to distill the essential concepts from the first seven chapters of this book, focusing on the boot process, the secure boot process, and the infection techniques used by bootkits.

## The Windows Boot Process

The boot process is the series of steps a computer system follows to initialize hardware and load the operating system (OS). This process can be broken down into several stages, each critical for preparing the system for use.

![high-level-windows-boot-process.png](/assets/img/posts/malware/bootkits-and-rootkits/high-level-windows-boot-process.png)

### BIOS andd Preboot environment
When you power on a computer, the first step is the **Power-On Self-Test (POST)**. During POST, the system performs diagnostics on the hardware components, ensuring everything is functioning correctly. This includes checking the memory, processor, and other essential peripherals. If any hardware issues are detected, POST will alert the user through error messages or beeps, halting the boot process.

Once POST is complete, the system's **BIOS (Basic Input/Output System)** takes over. The BIOS is firmware stored on a chip on the motherboard, responsible for initializing hardware components and preparing the system to load the operating system. This simplified I/O interface first becomes
available in the preboot environment, and is later replaced by different operating system abstractions. The most interesting of these services in terms of bootkit analysis is the **disk service**, accessible through a special handler known as the interrupt 13h handler, or simply **INT 13h**. More on this later.

After the BIOS has initialized the hardware, it proceeds to search for a bootable device. This device can be a hard drive, SSD, or a removable drive such as a USB stick or CD/DVD. The BIOS uses a predefined boot order to determine which device to check first. This is achieved by the Master Boot Record.

### The Master Boot Record (MBR)
The MBR is a data structure containing information on hard drive partition and the boot code
Its primary function is to identify the active partition containing the operating system's boot sector. Once the active partition is determined, the MBR reads and executes its boot code to start the loading process of the OS.

The MBR structure looks like the following: 
``` c
typedef struct _MASTER_BOOT_RECORD{
	BYTE bootCode[0x1BE]; // space to hold actual boot code
	MBR_PARTITION_TABLE_ENTRY partitionTable[4];
	USHORT mbrSignature; // set to 0xAA55 to indicate PC MBR format
} MASTER_BOOT_RECORD, *PMASTER_BOOT_RECORD;
```

- **BootCode (446 bytes)**: This small piece of code is responsible for loading the **Volume Boot Record (VBR)** in the first sector of the active partition and transfers control to it. 
- **Partition Table (64 bytes)**: Following the bootloader, contains entries for up to four primary partitions on the disk. Each entry includes details like the partition type, starting and ending sectors, and whether the partition is active (bootable).
- **Boot Signature (2 bytes)**: A magic number (0x55AA) that indicates the end of the MBR. This signature is essential for the BIOS to recognize the MBR as valid.

#### The BootCode
The boot code is the small piece of code stored within the MBR. This initial bootloader code, sometimes referred to as the "first-stage bootloader," has the critical task of loading a more complex bootloader or boot manager, often located in a specific partition. The first-stage bootloader’s primary responsibility is to locate and load the "second-stage bootloader" into memory. This second-stage bootloader is responsible for loading the operating system kernel.

For example, in a typical Linux system using GRUB (GRand Unified Bootloader), the first-stage bootloader in the MBR loads the GRUB second-stage bootloader from a designated partition. GRUB then presents a menu to the user, allowing them to select from multiple operating systems or kernels. In the case of Windows OS, the second-stage bootloader is called the *bootmgr* which, in essence, does the same task as GRUB. 

#### The MBR Partition Table
The partition table is a data structure that provides information about the partitions on the disk. It includes details such as the size, location, and type of each partition. 
``` c
typedef struct _MBR_PARTITION_TABLE_ENTRY {
	BYTE status; // active? 0=no, 128=yes
	BYTE chsFirst[3]; // starting sector number
	BYTE type; // OS type indicator code
	BYTE chsLast[3]; // ending sector number
	DWORD lbaStart; // first sector relative to start of disk
	DWORD size; // number of sectors in partition
} MBR_PARTITION_TABLE_ENTRY, *PMBR_PARTITION_TABLE_ENTRY;
```

Typically, a disk can have up to four primary partitions, one of which can be an extended partition that contains additional logical partitions. The partition table helps the system understand how the storage space on the disk is divided and where each partition begins and ends.

Look at this example:

![mbr-partition-table-example.png](/assets/img/posts/malware/bootkits-and-rootkits/mbr-partition-table-example.png)

The image shows two entries (the top two lines) indicating there are only two partitions on the disk. The first partition entry starts at the address 0x7DBE. Its first byte shows this partition is **active** (0x80), so the MBR boot code loads and executes its **Volume Boot Record (VBR)**, which is the first sector of that partition. The byte at offset 0x7DC2 indicates the partition type, such as the filesystem type expected by the OS, bootloader, or other low-level disk access code. In this case the value is 0x07, which corresponds to Microsoft’s NTFS.

The DWORD at 0x7DC5 in the partition table entry shows the partition starts at offset 0x800 from the beginning of the hard drive, measured in sectors. The last DWORD specifies the partition’s size in sectors (0x32000). This table summaries the values in the MBR partition table of the image. 

| Partition index | Is active | Type        | Beginning offset,<br>sectors (bytes) | Partition size,<br>sectors (bytes) |
| --------------- | --------- | ----------- | ------------------------------------ | ---------------------------------- |
| 0               | True      | NTFS (0x07) | 0x800<br>(0x100000)                  | 0x32000<br>(0x6400000)             |
| 1               | False     | NTFS (0x07) | 0x32800<br>(0x6500000)               | 0x4FCD000<br>(0x9F9A00000)         |
| 2               | N/A       | N/A         | N/A                                  | N/A                                |
| 3               | N/A       | N/A         | N/A                                  | N/A                                |

### The Volume Boot Record (VBR) and Initial Program Loader (IPL)

The Volume Boot Record, also known as the partition boot sector, resides in the first sector of a partition on a storage device. Unlike the Master Boot Record (MBR), which contains information about the disk as a whole and its partition table, the VBR is specific to each partition. 

The **Volume Boot Record (VBR)** holds essential information about the partition, including the filesystem type and its parameters, as well as executable code responsible for loading the **Initial Program Loader (IPL)** from the active partition. The IPL, in turn, contains the necessary logic to parse the filesystem, enabling it to read files from the partition.

#### The VBR Structure
The VBR typically contains the following elements:

1. **Boot Code**: The code responsible for loading the IPL
2. **BIOS Parameter Block (BPB)**: A data structure that stores information about the file system on the partition, such as the sector size, cluster size, and the number of sectors per track. This information is crucial for the boot code to correctly interpret and access the file system on the partition.
3. **Text Strings**: Used to display them to a user if an error occurs.
4. **Signature:** A 2-byte signature of the VBR, **0xAA55**. 

```c
typedef struct _BIOS_PARAMETER_BLOCK_NTFS {
	WORD SectorSize;
	BYTE SectorsPerCluster;
	WORD ReservedSectors;
	BYTE Reserved[5];
	BYTE MediaId;
	BYTE Reserved2[2];
	WORD SectorsPerTrack;
	WORD NumberOfHeads;
	DWORD HiddenSectors;
	BYTE Reserved3[8];
	QWORD NumberOfSectors;
	QWORD MFTStartingCluster;
	QWORD MFTMirrorStartingCluster;
	BYTE ClusterPerFileRecord;
	BYTE Reserved4[3];
	BYTE ClusterPerIndexBuffer;
	BYTE Reserved5[3];
	QWORD NTFSSerial;
	BYTE Reserved6[4];
} BIOS_PARAMETER_BLOCK_NTFS, *PBIOS_PARAMETER_BLOCK_NTFS;

typedef struct _BOOTSTRAP_CODE{
	BYTE bootCode[420]; // boot sector machine code
	WORD bootSectorSignature; // 0x55AA
} BOOTSTRAP_CODE, *PBOOTSTRAP_CODE;

typedef struct _VOLUME_BOOT_RECORD{
	 WORD jmp;
	BYTE nop;
	DWORD OEM_Name
	DWORD OEM_ID; // NTFS
	BIOS_PARAMETER_BLOCK_NTFS BPB;
	BOOTSTRAP_CODE BootStrap;
} VOLUME_BOOT_RECORD, *PVOLUME_BOOT_RECORD;
```

When the BIOS or UEFI identifies a bootable partition, it reads and executes the VBR's boot code. This boot code is responsible for locating the Initial Program Loader (IPL), which location is specified by the *HiddenSectors* field in the BPB structure. This field contains the offset (in sectors) from the beginning of the hard drive. The VBR's boot code loads the IPL into memory and transfers control to it, marking the next phase of the boot process.

![vbr-structure.png](/assets/img/posts/malware/bootkits-and-rootkits/vbr-structure.png)


#### The Initial Program Loader (IPL)
The IPL's primary functions include loading the complete bootloader, locating and loading the operating system kernel, and managing boot configurations. It also enables the system to boot various operating systems or kernel versions, allowing users to select their desired boot option.

The Initial Program Loader (IPL) **typically occupies 15 consecutive sectors of 512 bytes each** and is situated immediately after the Volume Boot Record (VBR). It contains just enough code to parse the partition’s filesystem and proceed with loading the boot manager module. The VBR and IPL work in tandem because the VBR, limited to a single sector, lacks the necessary space to include comprehensive filesystem parsing functionality on its own.


### The *bootmgr* Module and Boot Configuration Data (BCD)
The Initial Program Loader (IPL) reads and loads the operating system's boot manager, for Windows the *bootmgr* module, from the filesystem. Once the IPL hands over control to *bootmgr*, it takes charge of the boot process. Bootmgr reads the Boot Configuration Data (BCD), which includes critical system parameters that influence security policies, such as the Kernel-Mode Code Signing Policy.

Bootmgr continues managing the boot process until the user selects a boot option. After the user makes a choice, bootmgr launches *winload.exe* (or winresume.exe), which loads the operating system kernel, boot-start drivers, and some system registry data.

>**Aside: Real Mode vs Protected Mode**
> 
> When a computer is first powered on, the CPU starts in real mode, an outdated execution mode that uses a 16-bit memory model. In this mode, each byte in RAM is addressed by a pointer made up of two 2-byte words: segment_start and segment_offset. This segment memory model divides the address space into segments, where the address of each byte is determined by the segment's address and the offset of the byte within that segment. Specifically, segment_start identifies the target segment, while segment_offset specifies the byte's position within that segment.
> 
> Real mode addressing limits the accessible system RAM to about 1 MB, as the highest address possible is FFFF, which equates to 1,114,095 bytes. This limitation is insufficient for modern operating systems and applications. To overcome this, once bootmgr takes over the boot process, it switches the processor from real mode to protected mode (or long mode on 64-bit systems). The bootmgr consists of 16-bit real-mode code and a compressed PE image. The real-mode code uncompresses the PE image, switches the CPU to protected mode, and transfers control to the uncompressed module.
> 
> Bootkits need to handle this mode switch effectively to maintain control over the boot process. After the switch, the memory layout changes significantly, and code that was previously in a contiguous memory block may be relocated to different segments. Bootkits must incorporate sophisticated techniques to navigate these changes and retain control of the boot sequence.
>![real-and-protected-modes.png](/assets/img/posts/malware/bootkits-and-rootkits/real-and-protected-modes.png)

#### BCD Boot Variables
The BCD store holds all the information bootmgr needs to load the OS. This includes the partition path for the OS, available boot applications, code integrity settings, and parameters for booting in modes like preinstallation or safe mode. Some BCD boot variables are pretty important while analyzing bootkits due to the direct impact they have over some security checks:

| Variable name                                 | Description                                                                                                  | Type    | Parameter ID |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------------ | ------- | ------------ |
| *BcdLibraryBoolean_DisableIntegrityCheck*     | Disables kernel-mode<br>code integrity checks                                                                | Boolean | 0x16000048   |
| *BcdOSLoaderBoolean_WinPEMode*                | Tells the kernel to load in preinstallation mode, disabling kernel-mode code integrity checks as a byproduct | Boolean | 0x26000022   |
| *BcdLibraryBoolean_AllowPrereleaseSignatures* | Enables test signing<br>(TESTSIGNING)                                                                        | Boolean | 0x1600004    |



-----
**Secure Boot Process**

With the basic boot process understood, we can now delve into the secure boot process. Secure Boot is a critical security feature designed to ensure that a device boots using only software that is trusted by the Original Equipment Manufacturer (OEM). This mechanism is essential in preventing bootkits and other low-level malware from compromising the system.

Secure Boot leverages digital signatures to validate the integrity and authenticity of the boot software. Each piece of boot software, including the bootloader, operating system kernel, and drivers, is signed with a digital signature. These signatures are verified during the boot process to ensure that only trusted software is loaded.

The secure boot process typically involves the Unified Extensible Firmware Interface (UEFI), which is the modern replacement for the traditional BIOS. UEFI provides a more flexible and secure environment for initializing hardware and loading the operating system. It includes features such as a secure boot database, which contains trusted certificates and keys used to verify the digital signatures of boot software.

During the secure boot process, the UEFI firmware checks the digital signatures of all boot software against the secure boot database. If any software fails the signature verification, the boot process is halted, and the user is alerted to the security violation. This verification process ensures that any unauthorized or malicious code is prevented from executing during the boot process.

One of the significant benefits of Secure Boot is its ability to prevent unauthorized code execution during the boot process. By verifying the integrity of boot software, Secure Boot ensures that only trusted software is executed, protecting the system from bootkits and other low-level malware. This security feature is particularly important for preventing persistent and stealthy infections that can evade traditional security measures.

**[Suggested Image: Secure Boot Verification Process]**

A diagram illustrating the secure boot verification process could show how the UEFI firmware checks the digital signatures of boot software against the secure boot database. This visual representation can help in understanding the steps involved in ensuring a secure boot.

**Bootkit Infection Techniques**

With a solid understanding of the boot process and the secure boot process, we can now explore the infection techniques used by bootkits. Bootkits are a type of malware that infect the boot process to gain persistent and stealthy control over a system. They operate at a lower level than rootkits, often targeting the Master Boot Record (MBR) or Volume Boot Record (VBR).

Bootkit infection techniques are sophisticated and designed to achieve two primary goals: persistence and stealth. By infecting the boot process, bootkits ensure that they are loaded every time the system boots, making them difficult to remove. Additionally, by operating at a low level, bootkits can evade traditional detection methods, hiding their presence from the operating system and security software.

One common technique used by bootkits is MBR infection. The MBR is a small program located in the first sector of the bootable drive, responsible for loading the bootloader. By modifying the MBR, bootkits can alter the boot process to load malicious code before the operating system boots. This technique allows the bootkit to gain control of the system early in the boot process, ensuring its persistence and stealth.

An example of an MBR bootkit is TDL4, also known as Alureon. TDL4 modifies the MBR to redirect the boot process to its malicious code. This modification allows TDL4 to load its code before the operating system, providing it with control over the system and the ability to hide its presence from security software. TDL4 is known for its sophisticated rootkit capabilities, making it one of the most advanced bootkits in existence.

Another common technique used by bootkits is VBR infection. The Volume Boot Record (VBR) is a small program located in the first sector of a partition, responsible for loading the operating system kernel. Similar to MBR infections, VBR infections involve modifying the VBR to load malicious code before the operating system kernel. This technique allows bootkits to gain control of the system at a critical stage in the boot process.

Gapz is an example of a bootkit that uses advanced VBR infection techniques to remain undetected. Gapz modifies the VBR to load its malicious code, allowing it to execute before the operating system kernel. This early execution provides Gapz with control over the system and the ability to hide its presence from security software. Gapz is known for its stealthy infection techniques, making it a challenging threat to detect and remove.

Bootkits can also target the Initial Program Loader (IPL), which is a component of the boot process responsible for loading the operating system kernel. By modifying the IPL, bootkits can alter the boot process to load malicious code before the operating system kernel. This technique allows bootkits to gain control of the system at a critical stage in the boot process, ensuring their persistence and stealth.

**[Suggested Image: Bootkit Infection Process]**

A diagram illustrating the bootkit infection process could show how bootkits modify the MBR, VBR, or IPL to load malicious code before the operating system. This visual representation can help in understanding the techniques used by bootkits to achieve persistence and stealth.

**Conclusion**

Understanding the intricacies of the boot process, secure boot mechanisms, and bootkit infection techniques is crucial for cybersecurity professionals. This knowledge is essential for designing effective defensive strategies and forensic techniques to detect and mitigate bootkits and other advanced threats.

The first seven chapters of "Rootkits and Bootkits: Reversing Modern Malware and Next Generation Threats" provide a comprehensive foundation in these areas. The book offers detailed case studies and technical insights into the evolving landscape of boot-level malware, making it an invaluable resource for anyone interested in the field of cybersecurity.

By understanding the boot process, we can appreciate the importance of secure boot mechanisms in protecting our systems. Secure Boot ensures that only trusted software is executed during the boot process, preventing unauthorized code execution and thwarting bootkits. Additionally, by studying bootkit infection techniques, we can develop better defensive strategies to protect our systems from these advanced threats.

**[Suggested Image: Comprehensive Overview of Bootkit Mitigation Techniques]**

To wrap up, a diagram showing the comprehensive overview of bootkit mitigation techniques, including secure boot, detection methods, and removal strategies, could be beneficial. This visual aid can help in summarizing the key points discussed in this blog post.

Whether you are a seasoned security expert or new to the field, understanding these concepts is fundamental to enhancing your cybersecurity acumen. The detailed explanations and case studies provided in "Rootkits and Bootkits" will equip you with the knowledge needed to defend against these sophisticated threats and protect your systems from boot-level malware.