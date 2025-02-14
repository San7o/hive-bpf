# About Licensing

Licensing is an important topic when working with the linux kernel.
From the documentation (https://www.kernel.org/doc/html/v6.14-rc2/bpf/bpf_licensing.html):

> When a kernel module is loaded, the linux kernel checks which
> functions it intends to use. If any function is marked as
> “GPL only,” the corresponding module or program has to have GPL
> compatible license.

The accepted licenses are defined in `include/linux/license.h` and are:
- GPL
- GPLv2
- GPL and additional rights
- Dual BSD/GPL
- Dual MIT/GPL
- Dual MPL/GPL


