AC_INIT([kexec-lite], [1.0])
AM_INIT_AUTOMAKE()
AM_SILENT_RULES([yes])
AM_PROG_AS

AC_PROG_CC
AC_CONFIG_FILES([Makefile])
AC_CHECK_LIB([fdt], [fdt_create], [], [AC_MSG_ERROR([Could not find libfdt])])
AC_CHECK_LIB([elf], [elf_version], [], [AC_MSG_ERROR([Could not find libelf])])
AC_LANG(C)
AC_OUTPUT
