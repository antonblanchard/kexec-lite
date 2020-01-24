GIT_SHA1 ?= `git --work-tree=$(top_srcdir) --git-dir=$(top_srcdir)/.git describe --always --long --dirty || echo unknown`

sbin_PROGRAMS = kexec

kexec_SOURCES = kexec.c kexec_trampoline.S kexec_memory_map.c simple_allocator.c

kexec_CFLAGS = -Wall -O2 -ggdb3 -DGIT_SHA1=\"${GIT_SHA1}\"

