// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Google Inc, Steven Rostedt <rostedt@goodmis.org>
 */
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <ctype.h>
#include <fcntl.h>

#include "shelf.h"

#define EXEC_NAME	"shelf"

static void usage(char **argv)
{
	printf("usage: %s elf-file\n"
	       "\n", EXEC_NAME);
	exit(-1);
}

static void __vdie(const char *fmt, va_list ap, int err)
{
	int ret = errno;

	if (err && errno)
		perror(EXEC_NAME);
	else
		ret = -1;

	fprintf(stderr, "  ");
	vfprintf(stderr, fmt, ap);

	fprintf(stderr, "\n");
	exit(ret);
}

void pdie(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	__vdie(fmt, ap, 1);
	va_end(ap);
}

void die(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	__vdie(fmt, ap, 0);
	va_end(ap);
}

static void load_symbols(struct shelf *shelf, union Elf_Shdr *shdr)
{
	shelf->symoff = shdr_offset(shelf, shdr);
	shelf->symsize = shdr_size(shelf, shdr);
	shelf->symentsize = shdr_entsize(shelf, shdr);
	if (shelf->symentsize)
		shelf->symnum = shelf->symsize / shelf->symentsize;
	else
		shelf->symnum = 0;
}

static int shdr_cmp(const void *A, const void *B, void *data)
{
	struct shelf *shelf = data;
	union Elf_Shdr * const *a = A;
	union Elf_Shdr * const *b = B;
	uint64_t addr_a, addr_b;

	addr_a = shdr_addr(shelf, *a);
	addr_b = shdr_addr(shelf, *b);

	if (addr_a < addr_b)
		return -1;

	return addr_a == addr_b;
}

static struct shelf *local_shelf;

static int shdr_key_cmp(const void *A, const void *B)
{
	struct shelf *shelf = local_shelf;
	const uint64_t *a = A;
	union Elf_Shdr * const *b = B;
	uint64_t addr_a;
	uint64_t addr_b;
	uint64_t size_b;

	addr_a = *a;
	addr_b = shdr_addr(shelf, *b);
	size_b = shdr_size(shelf, *b);

	if (addr_a >= addr_b && addr_a < (addr_b + size_b))
		return 0;

	if (addr_a < addr_b)
		return -1;

	return 1;
}

union Elf_Shdr *find_section(struct shelf *shelf, uint64_t addr)
{
	union Elf_Shdr **pshdr;

	if (!shelf->fileshnum)
		return NULL;

	local_shelf = shelf;

	pshdr = bsearch(&addr, shelf->shdrs, shelf->fileshnum, sizeof(*pshdr),
			shdr_key_cmp);

	if (!pshdr)
		return NULL;

	return *pshdr;
}

static void read_sections(struct shelf *shelf)
{
	union Elf_Shdr **shdrs;
	union Elf_Shdr *shdr;
	const char *name;
	uint64_t addr;
	uint32_t type;
	int i;

	shelf->shdrs = 0;
	shelf->fileshnum = 0;

	for (i = 0; i < shelf->shnum; i++) {
		shdr = get_shdr(shelf, i);
		type = shdr_type(shelf, shdr);

		switch (type) {
		case SHT_SYMTAB:
			load_symbols(shelf, shdr);
			break;
		case SHT_STRTAB:
			name = shdr_name(shelf, shdr);
			if (strcmp(name, ".strtab") != 0)
				break;

			shelf->strings = shelf->map + shdr_offset(shelf, shdr);
			shelf->strsize = shdr_size(shelf, shdr);
			break;
		}
		addr = shdr_addr(shelf, shdr);
		if (type != SHT_NOBITS && addr) {
			shdrs = realloc(shelf->shdrs, (shelf->fileshnum + 1) * sizeof(*shdrs));
			if (!shdrs)
				pdie("Allocating sections");
			shdrs[shelf->fileshnum++] = shdr;
			shelf->shdrs = shdrs;
		}
	}
	if (shelf->shdrs)
		qsort_r(shelf->shdrs, shelf->fileshnum, sizeof(*shdrs), shdr_cmp, shelf);
}

int section_completion(struct ccli *ccli, struct shelf *shelf,
		       char ***list, int word, uint32_t type)
{
	union Elf_Shdr *shdr;
	const char *name;
	char **words;
	int i, s;

	words = calloc(shelf->shnum, sizeof(char *));
	if (!words)
		return 0;
	for (i = 0, s = 0; i < shelf->shnum; i++) {
		shdr = get_shdr(shelf, i);
		if (type && type != shdr_type(shelf, shdr))
			continue;

		name = shdr_name(shelf, get_shdr(shelf, s));
		if (name)
			words[s] = strdup(name);
		s++;
	}
	*list = words;
	return s;
}

int symbol_completion(struct ccli *ccli, struct shelf *shelf,
		      char ***list, int word)
{
	const char *name;
	char **words;
	int i;

	words = calloc(shelf->symnum, sizeof(char *));
	if (!words)
		return 0;

	for (i = 0; i < shelf->symnum; i++) {
		name = sym_name(shelf, get_sym(shelf, i));
		if (name)
			words[i] = strdup(name);
	}
	*list = words;
	return i;
}

static void setup_elf_info(struct shelf *shelf)
{
	union Elf_Ehdr *ehdr = shelf->ehdr;
	union Elf_Shdr *shstr;
	bool little;
	long test = 1;
	char *type;
	uint16_t idx;

	switch (ehdr->h64.e_type) {
	case ET_NONE:
		type = "NONE";
		break;
	case ET_REL:
		type = "RELOCATABLE";
		break;
	case ET_EXEC:
		type = "EXEUTABLE";
		break;
	case ET_DYN:
		type = "SHARED OBJECT";
		break;
	case ET_CORE:
		type = "CORE FILE";
		break;
	default:
		type = "UNKNOWN";
	}
	printf("ELF file: %s\n", shelf->file);
	printf("  %s (%d)\n", type, shelf->ehdr->h64.e_type);

	switch (ehdr->h64.e_ident[EI_CLASS]) {
	case ELFCLASS32:
		shelf->sixtyfour = false;
		printf("  32 bit\n");
		break;
	case ELFCLASS64:
		shelf->sixtyfour = true;
		printf("  64 bit\n");
		break;
	case ELFCLASSNONE:
	default:
		pdie("Unknown word size");
	}

	little = !!((char *)(&test))[0];

	switch (ehdr->h64.e_ident[EI_DATA]) {
	case ELFDATA2LSB:
		shelf->endian = little ? ENDIAN_SAME : ENDIAN_LITTLE;
		printf("  Little endian\n");
		break;
	case ELFDATA2MSB:
		shelf->endian = !little ? ENDIAN_SAME : ENDIAN_BIG;
		printf("  Big endian\n");
		break;
	case ELFDATANONE:
	default:
		pdie("Unknown endian file");
	}

	shelf->shnum = ehdr_shnum(shelf);
	shelf->shoff = ehdr_shoff(shelf);
	shelf->shentsize = ehdr_shentsize(shelf);
	idx = ehdr_shstrndx(shelf);

	shstr = get_shdr(shelf, idx);

	shelf->shstrings = shelf->map + shdr_offset(shelf, shstr);

	read_sections(shelf);
}

int main (int argc, char **argv)
{
	struct ccli *ccli;
	struct shelf shelf;
	struct stat st;

	if (argc < 2)
		usage(argv);

	memset(&shelf, 0, sizeof(shelf));

	shelf.file = argv[1];
	shelf.fd = open(argv[1], O_RDONLY);
	if (shelf.fd < 0)
		pdie("%s", argv[1]);

	if (stat(shelf.file, &st) < 0)
		pdie("stat on %s", argv[1]);

	shelf.size = st.st_size;

	shelf.map = mmap(NULL, shelf.size, PROT_READ, MAP_PRIVATE, shelf.fd, 0);
	if (shelf.map == MAP_FAILED)
		pdie("Failed on mmap of %s", argv[1]);

	shelf.ehdr = shelf.map;
	if (memcmp(shelf.ehdr->h64.e_ident, ELFMAG, SELFMAG) != 0)
		die("%s is not an ELF file", argv[1]);

	setup_elf_info(&shelf);

	ccli = ccli_alloc("shelf> ", STDIN_FILENO, STDOUT_FILENO);
	if (!ccli)
		pdie("ccli initialization");

	ccli_register_command(ccli, "list", list_cmd, &shelf);
	ccli_register_completion(ccli, "list", list_completion);

	ccli_register_command(ccli, "dump", dump_cmd, &shelf);
	ccli_register_completion(ccli, "dump", dump_completion);

	ccli_loop(ccli);
	ccli_free(ccli);

	return 0;
}
