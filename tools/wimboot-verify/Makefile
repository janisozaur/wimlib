CC32    := i686-w64-mingw32-gcc
CC64    := x86_64-w64-mingw32-gcc
PROJECT := wimboot-verify
CFLAGS  := -O2 -std=c99 -municode -Wall -Wextra -Wno-sign-compare -s
EXE32   := $(PROJECT).exe
EXE64   := $(PROJECT)-x64.exe
EXE     := $(EXE32) $(EXE64)
SRC     := wimboot-verify.c sha1.c
HEADERS := sha1.h
ZIPFILE := $(PROJECT).zip

all:$(EXE)

$(EXE32):$(SRC) $(HEADERS)
	$(CC32) $(CFLAGS) $(SRC) -o $@
$(EXE64):$(SRC) $(HEADERS)
	$(CC64) $(CFLAGS) $(SRC) -o $@

dist: $(ZIPFILE)

$(ZIPFILE): $(EXE)
	rm -f $(ZIPFILE)
	zip $(ZIPFILE) . --recurse-paths --exclude=.git/* --exclude=$(ZIPFILE)

clean:
	rm -f $(EXE) $(ZIPFILE)

.PHONY: all dist clean
