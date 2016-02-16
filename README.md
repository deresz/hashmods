# Hashmods #

This tool returns hashes of all the loaded modules in the systems. Should be used together with autorunsc to capture all the hashes from the system. Then you can use vt_autoruns.py to query all the collected hashes against VirusTotal. It's very very quick-and-dirty modification of https://github.com/rjoudrey/mdmp (don't even try to understand the code!)

Why do we need thing like this if we have autorunsc ? Well, it's very simple. Imagine you have a malware that adds something like this to one of the autoruns registry key (like ...\CurrentVersion\Run):

```
rundll32.exe %AppData%\malware.dll,malfunc
```

Guess what hash you would get with autoruns ? You are right, the hash of rundll32.exe :-) Hope it's clear now.

Does not seem to work with Windows 10.