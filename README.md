kexec-lite
==========

A simple kexec for flattened device tree platforms, on PowerPC.

Dependencies
------------

Requires Make, a C toolchain, and the libraries libelf and libfdt.

Ubuntu:
```sudo apt-get install automake libelf-dev libfdt-dev```

Fedora:
```sudo dnf install automake elfutils-libelf-devel libfdt-devel```

Building
------------
```
./bootstrap.sh
./configure
make
```

The output binary is called `kexec`
