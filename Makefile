PACKAGE=runtime
PROG=	kldinfo
MAN=	kldinfo.8

LIBADD= elf xo

.include <bsd.prog.mk>
