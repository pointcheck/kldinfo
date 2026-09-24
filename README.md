## kldinfo

FreeBSD utility to display dependency and version information about kernel
loadable objects held in KLD module (.ko) file

## SYNOPSIS

```
kldinfo [-rv] file
```

## DESCRIPTION
The ```kldinfo``` utility parses ELF header of KLD _file.ko_,
then searches for available Kernel Loadable objects and shows their dependency
and version information. If path to the file is given the utility tries to
open it directly, it quits if open fails. Otherwise, it searches for _file.ko_
in directories set by **kern.module_path** sysctl variable.

The **.ko** extension name is not mandatory, it will be added while searching
for the _file_ .  It does not hurt to specify it though.

The following options are available:

  **-r** - Extract version information of found objects. Otherwise print
only dependencies.

  **-v** - Be more verbose when parsing ELF.

## NOTES

The kernel file **/boot/kernel/kernel** can also be used as parameter. In this
case ```kldinfo``` will show all modules builtin into the kernel along with
their corresponding information. Note, the output can be very excessive.

## FILES

  **/boot/kernel** - default directory containing loadable modules.
Modules must have an extension of **.ko** .

## EXIT STATUS

The ```kldinfo``` utility exits 0 on success, and >0 if an error occurs.

## EXAMPLES

To show info about module by module name:

```kldinfo foo```

To show info about module by file name within the module path:

```kldinfo foo.ko```

To show info about module by relative path:

```kldinfo ./foo.ko```

Or by full path:

```kldinfo /boot/kernel/foo.ko```

## SEE ALSO
	kldload(8)
	kldstat(8)
	sysctl(8)

## AUTHORS

Ruslan Zalata <rz@fabmicro.ru>

## LICENSE

SPDX-License-Identifier: BSD-2-Clause

