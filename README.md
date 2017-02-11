```
    __  __           __   _____           
   / / / /___ ______/ /__/ ___/__  _______
  / /_/ / __ `/ ___/ //_/\__ \/ / / / ___/
 / __  / /_/ / /__/ ,<  ___/ / /_/ (__  ) 
/_/ /_/\__,_/\___/_/|_|/____/\__, /____/  
                            /____/        
			Extreme Vulnerable Driver
							Exploits
```

### HackSys Extreme Vulnerable Driver - ArbitraryOverwrite Exploit using GDI

Arbitrary Overwrite exploit; which exploits a vulnerable function within the HEVD Kernel driver and let us overwrite arbitrary data within Kernelland.

* Instead of overwriting nt!HalDispatchTable+4 and using NtQueryIntervalProfile(), this time we're (ab)using GDI to read/write Arbitrary data within Kernelland and let us bypass KASLR and SMEP kernel protection. 
* This technique is documented by Diego Juarez from Core Security in the following Blog post: (https://www.coresecurity.com/blog/abusing-gdi-for-ring0-exploit-primitives), so for a good understanding of this technique i recommend you to read this great post.
* Another great tutorial from @FuzzySec on GDI Bitmap Abuse is available at (http://www.fuzzysecurity.com/tutorials/expDev/21.html).
* In the latest version of this exploit i'm using the GDI Reloaded technique from Core Security, which bypasses kernel protection even in the latest version of Windows 10: https://www.coresecurity.com/system/files/publications/2016/10/Abusing-GDI-Reloaded-ekoparty-2016_0.pdf

  
Runs on:

```
This exploits has been tested on Windows 7 x86, Windows 8.1 x64 and Windows 10 build 1611
This exploits has been tested on Windows 7 x86 and Windows 8.1 x64, but should run successfully on any version lower then Windows 10 < build v1607.
``` 

Compile Exploit:

```
This project is written in C and can be compiled within Visual Studio.
```

Load Vulnerable Driver:

```
The HEVD driver can be downloaded from the HackSys Team Github page and loaded with the OSR Driver loader utility.
To run on x64, you need to install the Windows Driver Kit (WDK), Windows SDK and recompile with Visual Studio.
```
