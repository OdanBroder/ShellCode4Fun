Windows

```
nasm -f win32 shellcode.asm -o shellcode.obj
link shellcode.obj /subsystem:console /entry:main /out:shellcode.exe kernel32.lib user32.lib
nasm -f win64 shellcode.asm -o shellcode.obj
link shellcode.obj /subsystem:console /entry:main /out:shellcode.exe kernel32.lib user32.lib
```