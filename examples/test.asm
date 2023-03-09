mov rdx, 0x2222
mov rax, 0xA5
push rdx
cdq
mov dl, al
shr al, 4
shl dx, 8
or ax, dx
and ax, 0x0F0F
chk_al:
  cmp al, 0x9
  jl chk_ah
  add al, 7
chk_ah:
  cmp ah, 0x9
  jl fin
  add ah, 7
fin:
  add ax, 0x3030
