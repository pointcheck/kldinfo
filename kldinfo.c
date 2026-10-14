/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Ruslan Zalata <rz@fabmicro.ru>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/stat.h>

#include <err.h>
#include <gelf.h>
#include <errno.h>
#include <fcntl.h>
#include <libelf.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#define	DEPEND_ON	"_depend_on_"
#define	FIRMWARE	"firmware_list"
#define	METADATA	"_metadata"
#define	MODULE_PATH	"kern.module_path"
#define	SYSCTL		"sysctl__"
#define	VERSION		"_version"

static char		mod_file[MAXPATHLEN] = {0};
static const char 	*progname = NULL;
static bool		print_ver = false;
static bool		verbose = false;

static void
usage(void)
{
	fprintf(stderr, "usage: %s: [-rv] file ...\n", progname);
	exit(EX_USAGE);
}

/*
 * Extract KObj name from sym_name, dependency from subs and fine-print them.
 */
static void
fineprint_depend(char *sym_name, char *subs, uint32_t ver1, uint32_t ver2,
    uint32_t ver3)
{
	char *dep_name = subs + sizeof(DEPEND_ON) - 1;
	char *mod_name = sym_name + 1;
	int mod_name_len = subs - sym_name - 1;

	printf("MODULE: %-28.*s DEPENDS: %-28s VERSION: %7u %7u %7u\n",
		mod_name_len, mod_name, dep_name, ver1, ver2, ver3);
}

/*
 * Extract KObj name from sym_name and fine-print its version number.
 */
static void
fineprint_version(char *sym_name, char *subs, uint32_t ver1)
{
	char *obj_name = sym_name + 1;
	int obj_name_len = subs - sym_name - 1;

	printf("OBJECT: %-28.*s VERSION: %-7u\n", obj_name_len, obj_name, ver1);
}

/*
 * Search for module file by its name. If name is a pathname,
 * return this same name. Otherwise, search for .ko in directories set
 * by kern.module_path sysctl variable for matching module name.
 */
static char *
find_module_file(char *name)
{
	char *module_path;
	size_t module_path_len = 0;

	/* name is a file pathnames, use it! */
	if (index(name, '/') != NULL)
		return (name);
	if (sysctlbyname(MODULE_PATH, NULL,
			&module_path_len, NULL, 0) != 0) {
		fprintf(stderr, "%s: can't get sysctl %s size: %s\n", progname,
			MODULE_PATH, strerror(errno));
		return (NULL);
	}
	if ((module_path = (char *) malloc(module_path_len)) == NULL) {
		fprintf(stderr, "%s: can't malloc %zu bytes: %s\n", progname,
			module_path_len, strerror(errno));
		return (NULL);
	}
	if (sysctlbyname(MODULE_PATH, module_path,
			&module_path_len, NULL, 0) != 0) {
		fprintf(stderr, "%s: can't get sysctl %s value: %s\n", progname,
			MODULE_PATH, strerror(errno));
		return (NULL);
	}
	if (verbose)
		printf("Searching module name %s in module_path: %s\n",
			name, module_path);

	size_t found = 0;
	char *path;
	struct stat sb;

	while ((path = strsep(&module_path, ";")) != NULL) {
		if (strstr(name, ".ko") == NULL)
			snprintf(mod_file, MAXPATHLEN, "%s/%s.ko", path, name);
		else
			snprintf(mod_file, MAXPATHLEN, "%s/%s", path, name);
		if (verbose)
			printf("PATH: %s, mod_file: %s\n", path, mod_file);
		if (stat(mod_file, &sb) == 0) {
			found = 1;
			break;
		}
	}
	free(module_path);
	if (found) {
		if (verbose)
			printf("FOUND: %s\n", mod_file);
		return (mod_file);
	}
	if (verbose)
		printf("Module %s not found in module_path!\n", name);

	return (NULL);
}

/*
 * Parse ELF header of a given KLD module file, then search for available
 * Kernel Loadable objects, extract and show their dependency and version
 * information.
 */
static void
process_module_file(char *filename)
{
	size_t deps_count = 0, scn_stab = 0;
	Elf_Scn *elf_scn = NULL;
	Elf *elf;
	int fd;

	if ((fd = open(filename, O_RDONLY)) < 0)
		err(EX_NOINPUT, "can't open ELF file %s", filename);
	if ((elf = elf_begin(fd, ELF_C_READ, (Elf *) 0)) == 0)
		errx(EX_DATAERR, "ELF read error: %s", elf_errmsg(elf_errno()));
	if (elf_getshdrstrndx(elf, &scn_stab) < 0)
		errx(EX_DATAERR, "ELF has no string table: %s",
		    elf_errmsg(elf_errno()));
	if (verbose)
		printf("Section names are in section #%lu\n", scn_stab);

	GElf_Shdr sh;

	while ((elf_scn = elf_nextscn(elf, elf_scn))) {
		if (gelf_getshdr(elf_scn, &sh) == NULL) {
			warnx("no section header for %p", elf_scn);
			continue;
		}

		char *name = elf_strptr(elf, scn_stab, sh.sh_name);
		size_t stab = sh.sh_link;

		if (verbose)
			printf("Elf Section: name = %s, addr = 0x%lx"
				", stab = #%zu\n", name, sh.sh_addr, stab);

		Elf_Data *elf_data = NULL;

		while ((elf_data = elf_getdata(elf_scn, elf_data))) {
			if (verbose)
				printf("  Elf Data: off = 0x%lx, size = 0x%lu,"
					" type = %u\n",
					elf_data->d_off, elf_data->d_size,
					elf_data->d_type);
			if (strncmp(name, ".symtab", 7) != 0)
				continue;

			/* Extract symbols from .symtab section */

			GElf_Sym sym;
			size_t i = 0;

			while (gelf_getsym(elf_data, i++, &sym) == &sym) {

				/* Check is read symbol of a proper type */
				if (GELF_ST_TYPE(sym.st_info) != STT_OBJECT)
					continue;
				char *sym_name =
					elf_strptr(elf, stab, sym.st_name);
				if (verbose)
					printf("  Symbol = %s, info = 0x%02X,"
					    " sect = #%u, size = %lu,"
					    " addr = 0x%lx\n",
					    sym_name, sym.st_info, sym.st_shndx,
					    sym.st_size, sym.st_value);

				/* Access section of symbol data */
				Elf_Scn *scn = elf_getscn(elf, sym.st_shndx);
				if (scn == NULL) {
					if (verbose)
						printf("    "
						    "Cannot get section #%u\n",
						    sym.st_shndx);
					continue;
				}
				if (gelf_getshdr(scn, &sh) == NULL) {
					if (verbose)
						printf("\t\t"
						    "Cannot get SH for #%u\n",
						    sym.st_shndx);
					continue;
				}
				Elf_Data *data = elf_getdata(scn, NULL);
				if (data == NULL) {
					if (verbose)
						printf("    "
						    "Cannot get data for #%u\n",
						    sym.st_shndx);
					continue;
				}
				if (data->d_buf == NULL) {
					if (verbose)
						printf("    "
						  "No data buf for sec #%u\n",
						  sym.st_shndx);
					continue;
				}

				uint8_t *addr = (uint8_t *)data->d_buf +
				    sym.st_value - sh.sh_addr;
				uint32_t ver1, ver2, ver3;

				memcpy(&ver1, addr + 0, sizeof(ver1));
				memcpy(&ver2, addr + 4, sizeof(ver2));
				memcpy(&ver3, addr + 8, sizeof(ver3));
				if (verbose)
					printf("    "
					    "ver1 = 0x%0x (%u), "
					    "ver2 = 0x%0x (%u), "
					    "ver3 = 0x%0x (%u)\n",
					    ver1, ver1, ver2, ver2, ver3, ver3);

				if (strstr(sym_name, FIRMWARE) != NULL) {
					if (verbose) {
						printf("    Firmware list: ");
						for (size_t j = 0;
						    j < sym.st_size; j++)
							printf("%02X ",
							    addr[j]);
						printf("\n");
					}
					/* TO-DO */
				}

				char *subs;

				/* Kobj symbols begin with underscore */
				if (sym_name[0] != '_')
					continue;
				/* Hide metadata symbols */
				if ((subs = strstr(sym_name, METADATA)) != NULL)
					continue;
				/* Hide sysctl objects */
				if ((subs = strstr(sym_name, SYSCTL)) != NULL)
					continue;
				if ((subs = strstr(sym_name, DEPEND_ON)) != NULL) {
					fineprint_depend(sym_name, subs, ver1,
					    ver2, ver3);
					deps_count++;
					continue;
				}
				if (print_ver &&
				   (subs = strstr(sym_name, VERSION)) != NULL)
					fineprint_version(sym_name, subs, ver1);
			}
		}
	}
	elf_end(elf);
	if (deps_count)
		warnx("found %zu dependencies in %s", deps_count, filename);
	else
		errx(EX_DATAERR, "ELF file %s is not a KLD module!", filename);
}

/*
 * This utility prints dependency and version info for given list of modules
 * by parsing ELF header of each module file and extracting data from symbols.
 * It finds module(s) either by searching .ko file with same name in directories
 * set by kern.module_path sysctl variable, or by using name as a file name if
 * it's a pathname. Can be used to show built-in modules in kernel file.
 */
int
main(int argc, char *argv[])
{
	char *filename = NULL;
	int opt;

	if (elf_version(EV_CURRENT) == EV_NONE)
		errx(EX_SOFTWARE, "ELF library too old");

	progname = getprogname();
	while ((opt = getopt(argc, argv, "rv")) != -1) {
		switch (opt) {
		case 'r':
			print_ver = true;
			break;
		case 'v':
			verbose = true;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc == 0)
		usage();
	while (argc-- != 0) {
		if ((filename = find_module_file(argv[0])) == NULL)
			errx(EX_NOINPUT, "can't find file for %s", argv[0]);
		process_module_file(filename);
		argv++;
	}
	return (0);
}
