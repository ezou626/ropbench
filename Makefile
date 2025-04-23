GCC=gcc
CLG=clang

UNGUARDED_FLAGS= -O0 -fno-stack-protector -z execstack -g -fno-pie -no-pie -std=c89
WXORX_FLAGS=-fno-stack-protector -g -fno-pie -no-pie -std=c89
DEFAULT_FLAGS=-g -std=c89

all: bin/clang_unguarded bin/gcc_unguarded bin/clang_wxorx bin/gcc_wxorx bin/clang_default bin/gcc_default

unguarded: bin/clang_unguarded bin/gcc_unguarded
	@echo "Unprotected binaries created."

wxorx: bin/clang_wxorx bin/gcc_wxorx
	@echo "WXORX binaries created."

default: bin/clang_default bin/gcc_default
	@echo "Default binaries created."

bin/clang_unguarded: src/vulnerable_code.c
	$(CLG) $(UNGUARDED_FLAGS) -o bin/clang_unguarded src/vulnerable_code.c

bin/gcc_unguarded: src/vulnerable_code.c
	$(GCC) $(UNGUARDED_FLAGS) -o bin/gcc_unguarded src/vulnerable_code.c

bin/clang_wxorx: src/vulnerable_code.c
	$(CLG) $(WXORX_FLAGS) -o bin/clang_wxorx src/vulnerable_code.c

bin/gcc_wxorx: src/vulnerable_code.c
	$(GCC) $(WXORX_FLAGS) -o bin/gcc_wxorx src/vulnerable_code.c

bin/clang_default: src/vulnerable_code.c
	$(CLG) $(DEFAULT_FLAGS) -o bin/clang_default src/vulnerable_code.c

bin/gcc_default: src/vulnerable_code.c
	$(GCC) $(DEFAULT_FLAGS) -o bin/gcc_default src/vulnerable_code.c

clean:
	rm ./bin/*