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

#include <gelf.h>
#include <errno.h>
#include <fcntl.h>
#include <libelf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <unistd.h>

#define	DEPEND_ON	"_depend_on_"
#define	VERSION		"_version"
#define	METADATA	"_metadata"
#define MODULE_PATH	"kern.module_path"

int verbose = 0;
const char *progname = NULL;
static char mod_file[MAXPATHLEN] = {0};

void
usage(void)
{
	fprintf(stderr, "usage: %s: [-rv] file\n", progname);
	exit(1);
}

void
fineprint_depend(char *sym_name, char *subs,
	uint32_t ver1, uint32_t ver2, uint32_t ver3)
{
	int mod_name_len = subs - sym_name;
	char mod_name[mod_name_len + 1];
	mod_name[0] = '\000';
	strncat(mod_name, sym_name + 1, mod_name_len - 1);

	char *dep_name = subs + sizeof(DEPEND_ON) - 1;
	int dep_name_len = strlen(sym_name - mod_name_len -
		sizeof(DEPEND_ON));

	printf("MODULE: %s\tDEPENDS: %s\tVERSION: %u %u %u\n",
		mod_name, dep_name, ver1, ver2, ver3);

}

void
fineprint_version(char *sym_name, char *subs, uint32_t ver1)
{
	int obj_name_len = subs - sym_name;
	char obj_name[obj_name_len + 1];
	obj_name[0] = '\000';

	if (sym_name[0] == '_') {
		sym_name++;
		obj_name_len--;
	}

	strncat(obj_name, sym_name, obj_name_len);

	printf("OBJECT: %s\tVERSION: %u\n", obj_name, ver1);
}

char *
find_module_file(char *name)
{
	if (index(name, '/') != NULL)
		return (name); /* name is a file path name, use it! */

	char *module_path;
	size_t module_path_len = 0;

	/* If getting module_path fails we quit returning NULL */

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

	char *path;
	int found = 0;
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

int
main(int argc, char *argv[])
{
	int fd;
	int ch;
	int print_ver = 0;
	int deps_count = 0;
	char *filename = NULL;
	Elf_Scn *elf_scn = NULL;
	Elf *elf;

	progname = getprogname();

	while ((ch = getopt(argc, argv, "vr")) != -1) {
		switch (ch) {
		case 'v':
			verbose = 1;
			break;
		case 'r':
			print_ver = 1;
			break;
		case '?':
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1)
		usage();

	if ((filename = find_module_file(argv[0])) == NULL) {
		fprintf(stderr, "%s: can't find file for %s\n", progname,
			argv[0]);
		return (1);
	}

	if ((fd = open(filename, O_RDONLY)) < 0) {
		fprintf(stderr, "%s: can't open ELF file %s: %s\n", progname,
			filename, strerror(errno));
		return (2);
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
		fprintf(stderr, "%s: ELF library too old\n", progname);
		return (3);
	}

	if ((elf = elf_begin(fd, ELF_C_READ, (Elf *) 0)) == 0) {
		fprintf(stderr, "%s: ELF read error: %s\n", progname,
			elf_errmsg(elf_errno()));
		return (4);
	}

	size_t scn_stab = 0;

	if (elf_getshdrstrndx(elf, &scn_stab) < 0) {
		fprintf(stderr, "%s: ELF has no string table: %s\n", progname,
			elf_errmsg(elf_errno()));
		return (5);
	}

	if (verbose)
		printf("Section names are in section #%lu\n", scn_stab);

	GElf_Shdr sh;

	while ((elf_scn = elf_nextscn(elf, elf_scn))) {

		if (gelf_getshdr(elf_scn, &sh) == NULL) {
			fprintf(stderr, "%s: no section header for %p\n",
				progname, elf_scn);
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
				printf("\tElf Data: off = 0x%lx, size = 0x%lu,"
					" type = %u\n",
					elf_data->d_off, elf_data->d_size,
					elf_data->d_type);

			if (strncmp(name, ".symtab", 7) != 0)
				continue;

			/* Extract symbols from .symtab section */

			int i = 0;
			GElf_Sym sym;

     			while (gelf_getsym(elf_data, i++, &sym) == &sym) {

				/* Symbol had been read */

				if (GELF_ST_TYPE(sym.st_info) != STT_OBJECT)
					continue; /* we look for data objects */

				char *sym_name =
					elf_strptr(elf, stab, sym.st_name);

				if (verbose)
					printf("\t\tSymbol = %s, info = 0x%02X,"
					  " sect = #%u, size = %lu,"
					  " addr = 0x%lx\n",
					  sym_name, sym.st_info, sym.st_shndx,
					  sym.st_size, sym.st_value);


				/* Access section of symbol data */

				Elf_Scn *scn = elf_getscn(elf, sym.st_shndx);

				if (scn == NULL) {
					if (verbose)
						printf("\t\t"
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
						printf("\t\t"
						  "Cannot get data for #%u\n",
						  sym.st_shndx);
					continue;
				}

				if (data->d_buf == NULL) {
					if (verbose)
						printf("\t\t"
						  "No data buf for sec #%u\n",
						  sym.st_shndx);
					continue;
				}

				uint32_t ver1 =
				  *(uint32_t *)((uint8_t *)data->d_buf +
					0 + sym.st_value - sh.sh_addr);

				uint32_t ver2 =
				  *(uint32_t *)((uint8_t *)data->d_buf +
					4 + sym.st_value - sh.sh_addr);

				uint32_t ver3 =
				  *(uint32_t *)((uint8_t *)data->d_buf +
					8 + sym.st_value - sh.sh_addr);

				if (verbose)
					printf("\t\t"
					  "ver1 = 0x%0x (%u), "
					  "ver2 = 0x%0x (%u), "
					  "ver3 = 0x%0x (%u)\n",
					  ver1, ver1, ver2, ver2, ver3, ver3);

				if (strstr(sym_name, "firmware_list") != NULL) {
					uint8_t *c = (uint8_t *)data->d_buf +
						sym.st_value - sh.sh_addr;
					if (verbose) {
						printf("\t\tFirmware list: ");
						for (int i = 0;
						    i < sym.st_size; i++)
							printf("%02X ", c[i]);
						printf("\n");
					}
				}

				char *subs;

				if ((subs = strstr(sym_name, DEPEND_ON)) != NULL) {
					fineprint_depend(sym_name, subs,
						ver1, ver2, ver3);
					deps_count++;
				} else
				if ((subs = strstr(sym_name, VERSION)) != NULL &&
				            strstr(sym_name, METADATA) == NULL) {
					if (print_ver)
						fineprint_version(sym_name,
							subs, ver1);
				}
			}
		}
	}

	elf_end(elf);

	if (deps_count)
		fprintf(stderr, "Found %u dependencies in file %s\n",
			deps_count, filename);
	else
		fprintf(stderr, "ELF file %s is not a KLD object!\n",
			filename);

	return (0);
}
