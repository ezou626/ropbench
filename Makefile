include env_vars
export

GCC=gcc

CFLAGS= -O0 $(ASLR) $(CANARY) $(WXORX) -g -std=c89

all: bin/overflow bin/ret2win

bin/overflow: src/overflow.c
	$(GCC) $(CFLAGS) -o bin/overflow src/overflow.c

bin/ret2win: src/ret2win.c
	$(GCC) $(CFLAGS) -o bin/ret2win src/ret2win.c

clean:
	find ./bin -type f ! -iname 'readme*' -delete