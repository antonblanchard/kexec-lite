
LIBFDT_CPPFLAGS =
LIBFDT_LIBADD = -lfdt

LIBELF_CPPFLAGS =
LIBELF_LIBADD = -lelf

LIBZ_CPPFLAGS =
LIBZ_LIBADD = -lz

CFLAGS = -Wall -O2 -ggdb3
LDFLAGS =
ASFLAGS =

all: kexec

kexec: CPPFLAGS += $(LIBFDT_CPPFLAGS) $(LIBELF_CPPFLAGS) $(LIBZ_CPPFLAGS)
kexec: LIBS += $(LIBFDT_LIBADD) $(LIBELF_LIBADD) $(LIBZ_LIBADD)

kexec: kexec.o kexec_trampoline.o kexec_memory_map.o simple_allocator.o
	$(LINK.o) -o $@ $^ $(LIBS)

clean:
	rm -f *.o kexec
