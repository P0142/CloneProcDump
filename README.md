# CloneProcDump
---
Takes in a PID and creates a clone of the process using NtCreateProcessEx, then dumps with minidump.

I wanted to spend some time getting a better understanding of windows subsystems, so I threw this together to create dumps. It uses NtCreateProcessEx to clone a process, then MiniDumpWriteDump with a callback function that writes the dump to memory(I've found using raw dumps is just a little bit painful, and minidumps are supported by pypykatz and other tools so this step is necessary), then we XOR encrypt the dump and finally write it to disk. If you were to dump lsass and then write it to disk without encoding or encrypting it you would set off defender and it would eat your dump. Currently not detected by defender, but does nothing to combat PPL, so it's basically useless.
It was fun to program and test though. I would recommend making your own process dumper if you have some extra time to kill.

Usage:
---
First create the dump.
```powershell
.\CloneProcDump.exe /pid:844 /x:"Hello World" /o:process.xdp
```
Copy it locally, then use the provided python script to remove Xor.
```bash
python XorRemover.py -d process.xdp -x "Hello World" -o clean.dmp
```

From here you can analyze with volatility or use pypykatz or w/e


Inspiration:
---
https://medium.com/@captain-woof/windows-process-cloning-how-to-dump-a-process-without-dumping-the-process-f3101cbea2e1

Reference:
---
https://github.com/huntandhackett/process-cloning/tree/master

https://www.huntandhackett.com/blog/the-definitive-guide-to-process-cloning-on-windows
