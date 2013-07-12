
LIBFDT_CPPFLAGS =
LIBFDT_LIBADD = -lfdt

LIBELF_CPPFLAGS =
LIBELF_LIBADD = -lelf

CFLAGS = -m32 -Wall -O2 -ggdb3
LDFLAGS = -m32
ASFLAGS = -m32

all: kexec

kexec: CPPFLAGS += $(LIBFDT_CPPFLAGS) $(LIBELF_CPPFLAGS)
kexec: LIBS += $(LIBFDT_LIBADD) $(LIBELF_LIBADD)

kexec: kexec.o kexec_trampoline.o kexec_memory_map.o simple_allocator.o
	$(LINK.o) -o $@ $^ $(LIBS)

clean:
	rm -f *.o kexec
