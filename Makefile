ifneq ("$(wildcard env_vars)","")
include env_vars
export
endif

ASLR ?=
CANARY ?=
WXORX ?=

GCC=gcc

CFLAGS= -O0 $(ASLR) $(CANARY) $(WXORX) -g -std=c89

all: bin/overflow bin/ret2win

bin/overflow: src/overflow.c
	$(GCC) $(CFLAGS) -o bin/overflow src/overflow.c

bin/ret2win: src/ret2win.c
	$(GCC) $(CFLAGS) -o bin/ret2win src/ret2win.c

bin/coalmine: src/coalmine.c
	$(GCC) $(CFLAGS) -o bin/coalmine src/coalmine.c

clean:
	find ./bin -type f ! -iname 'readme*' -delete