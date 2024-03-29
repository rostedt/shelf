// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Google Inc, Steven Rostedt <rostedt@goodmis.org>
 */
#include <regex.h>
#include <ctype.h>
#include <errno.h>
#include "shelf.h"

static void dump_line(struct ccli *ccli, struct shelf *shelf, uint64_t offset, int len)
{
	unsigned char ch;
	int save_len = len;
	int i;

	for (i = 0; i < 8; i++, offset++) {
		if (len && offset < shelf->size) {
			ch = *(unsigned char *)(shelf->map + offset);
			ccli_printf(ccli, "%02x ", ch);
			len--;
		} else
			ccli_printf(ccli, "   ");
	}

	ccli_printf(ccli, " ");
	for (i = 0; i < 8; i++, offset++) {
		if (len && offset < shelf->size) {
			ch = *(unsigned char *)(shelf->map + offset);
			ccli_printf(ccli, "%02x ", ch);
			len--;
		} else
			ccli_printf(ccli, "   ");
	}

	ccli_printf(ccli, " |");

	offset -= 16;
	len = save_len;

	for (i = 0; i < 16; i++, offset++) {
		if (len && offset < shelf->size) {
			ch = *(unsigned char *)(shelf->map + offset);
			if (isprint(ch))
				ccli_printf(ccli, "%c", ch);
			else
				ccli_printf(ccli, ".");
			len--;
		} else
				ccli_printf(ccli, " ");
	}
	ccli_printf(ccli, "|\n");
}

static void dump_lines(struct ccli *ccli, struct shelf *shelf, uint64_t offset, int len, int line)
{
	int ret;

	if (offset + len > shelf->size)
		len = shelf->size - offset;

	while (len) {
		ret = ccli_page(ccli, line, " \b");
		if (ret < 0)
			break;
		dump_line(ccli, shelf, offset, len);
		line = ret;
		offset += 16;
		if (len > 16)
			len -= 16;
		else
			len = 0;
	}
}

static void dump_usage(struct ccli *ccli)
{
	ccli_printf(ccli, "usage: dump section <start-addr>[ - <end-addr>| <size>]\n"
		    "usage: dump symbol <start-symbol>[ - <end-symbol>| <size>]\n");
}

static int dump_symbol_usage(struct ccli *ccli)
{
	ccli_printf(ccli, "usage: dump symbol <start-symbol>[ - <end-symbol>| <size>]\n");
	return 0;
}

static union Elf_Shdr *lookup_section(struct shelf *shelf, const char *sec)
{
	union Elf_Shdr *shdr;
	const char *name;
	int i;

	for (i = 0; i < shelf->shnum; i++) {
		shdr = get_shdr(shelf, i);
		name = shdr_name(shelf, shdr);
		if (name && strcmp(name, sec) == 0)
			return shdr;
	}
	return NULL;
}

static int dump_section(struct ccli *ccli, void *data,
			int argc, char **argv)
{
	struct shelf *shelf = data;
	union Elf_Shdr *shdr;
	int line = 1;

	shdr = lookup_section(shelf, argv[0]);
	if (!shdr) {
		ccli_printf(ccli, "Section '%s' not found\n", argv[0]);
		return 0;
	}

	line = ccli_page(ccli, line, "name:      %s\n", shdr_name(shelf, shdr));
	line = ccli_page(ccli, line, "type:      %d\n", shdr_type(shelf, shdr));
	line = ccli_page(ccli, line, "flags:     %llx\n", (long long)shdr_flags(shelf, shdr));
	line = ccli_page(ccli, line, "addr:      %llx\n", (long long)shdr_addr(shelf, shdr));
	line = ccli_page(ccli, line, "offset:    %llx\n", (long long)shdr_offset(shelf, shdr));
	line = ccli_page(ccli, line, "size:      %lld\n", (long long)shdr_size(shelf, shdr));
	line = ccli_page(ccli, line, "link:      %d\n", shdr_link(shelf, shdr));
	line = ccli_page(ccli, line, "info:      %x\n", shdr_info(shelf, shdr));
	line = ccli_page(ccli, line, "addralign: %llx\n", (long long)shdr_addralign(shelf, shdr));
	line = ccli_page(ccli, line, "entsize:   %llx\n\n", (long long)shdr_entsize(shelf, shdr));

	dump_lines(ccli, shelf, shdr_offset(shelf, shdr), shdr_size(shelf, shdr), line);

	return 0;
}

static union Elf_Sym *find_symbol(struct shelf *shelf, const char *sec)
{
	union Elf_Sym *sym;
	const char *name;
	int i;

	for (i = 0; i < shelf->symnum; i++) {
		sym = get_sym(shelf, i);
		name = sym_name(shelf, sym);
		if (name && strcmp(name, sec) == 0)
			return sym;
	}
	return NULL;
}

static int print_addr(struct ccli *ccli, struct shelf *shelf,
		       uint64_t addr, uint64_t offset, int line)
{
	if (shelf->sixtyfour)
		line = ccli_page(ccli, line, "%16zx:\t", addr);
	else
		line = ccli_page(ccli, line, "%8zx:\t", addr);

	if (line < 0)
		return -1;

	dump_line(ccli, shelf, offset, -1);
	return line;
}

static int dump_symbol(struct ccli *ccli, void *data,
		       int argc, char **argv)
{
	struct shelf *shelf = data;
	union Elf_Sym *sym;
	union Elf_Shdr *shdr;
	uint64_t start, stop;
	uint64_t addr, offset;
	uint64_t size;
	uint16_t shndx;
	int line = 1;
	int inc;

	if (argc < 1)
		return dump_symbol_usage(ccli);

	sym = find_symbol(shelf, argv[0]);
	if (!sym) {
		ccli_printf(ccli, "Symbol '%s' not found\n", argv[0]);
		return 0;
	}

	shndx = sym_shndx(shelf, sym);
	shdr = get_shdr(shelf, shndx);
	addr = shdr_addr(shelf, shdr);
	size = shdr_size(shelf, shdr);
	start = shdr_offset(shelf, shdr);

	offset = sym_value(shelf, sym);

	if (offset < addr || offset >= addr + size) {
		ccli_printf(ccli, "# sym %s offset %zx not in range %zx-%zx\n",
			    argv[0], offset, addr, addr + size);
		return 0;
	}

	start += offset - addr;

	if (argc < 2) {
		print_addr(ccli, shelf, addr, start, 1);
		return 0;
	}

	if (strcmp(argv[1], "-") == 0) {
		if (argc < 3)
			return dump_symbol_usage(ccli);

		sym = find_symbol(shelf, argv[2]);
		if (!sym)
			ccli_printf(ccli, "Symbol '%s' not found\n", argv[2]);


		shndx = sym_shndx(shelf, sym);
		if (shdr != get_shdr(shelf, shndx)) {
			ccli_printf(ccli, "Symbol '%s' in section '%s' not in same section\n"
				    "  as symbol '%s' in section '%s'\n",
				    argv[0], shdr_name(shelf, shdr),
				    argv[2], shdr_name(shelf, get_shdr(shelf, shndx)));
			return 0;
		}

		stop = start + sym_value(shelf, sym) - offset;
		if (stop < start) {
			ccli_printf(ccli, "Symbol '%s' is before symbol '%s'\n",
				    argv[2], argv[0]);
			return 0;
		}

		size = stop - start;
	} else {
		size = strtoll(argv[1], NULL, 0);
	}

	inc = shelf->sixtyfour ? 8 : 4;

	while (size > 0) {
		line = print_addr(ccli, shelf, addr, start, line);
		if (line < 0)
			break;
		addr += inc;
		start += inc;
		if (size < inc)
			break;
		size -= inc;
	}

	return 0;
}

static int dump_address(struct ccli *ccli, void *data,
			int argc, char **argv)
{
	struct shelf *shelf = data;
	union Elf_Shdr *shdr;
	const char *name;
	uint64_t offset;
	uint64_t addr;
	uint64_t end_addr;
	int line = 1;
	int inc;

	if (argc < 1)
		return 0; // TODO add usage

	errno = 0;
	addr = strtoull(argv[0], NULL, 0);
	if (errno) {
		ccli_printf(ccli, "%s: %s\n", argv[0], strerror(errno));
		return 0;
	}

	shdr = find_section(shelf, addr);
	if (!shdr) {
		ccli_printf(ccli, "No section found with address %zx %s\n", addr, argv[0]);
		return 0;
	}

	offset = addr - shdr_addr(shelf, shdr);
	offset += shdr_offset(shelf, shdr);

	name = shdr_name(shelf, shdr);

	if (argc < 2) {
		if (name)
			ccli_printf(ccli, "%s:\t", name);
		print_addr(ccli, shelf, addr, offset, 1);
		return 0;
	}

	if (strcmp(argv[1], "-") == 0) {
		if (argc > 2)
			end_addr = strtoull(argv[2], NULL, 0);
		else
			end_addr = shdr_addr(shelf, shdr) + shdr_size(shelf, shdr);
	} else {
		end_addr = strtoull(argv[1], NULL, 0);
		end_addr += addr;
	}

	if (end_addr > shdr_addr(shelf, shdr) + shdr_size(shelf, shdr))
		end_addr = shdr_addr(shelf, shdr) + shdr_size(shelf, shdr);

	if (name)
		line = ccli_page(ccli, line, "%s:\n", name);

	inc = shelf->sixtyfour ? 8 : 4;

	while (line >= 0 && addr < end_addr) {
		line = ccli_page(ccli, line, "  ");
		if (line < 0)
			return 0;
		line = print_addr(ccli, shelf, addr, offset, line);
		addr += inc;
		offset += inc;
	}

	return 0;
}

int dump_cmd(struct ccli *ccli, const char *command, const char *line,
	     void *data, int argc, char **argv)
{
	if (argc < 2) {
		dump_usage(ccli);
		return 0;
	}

	if (strcmp(argv[1], "section") == 0)
		return dump_section(ccli, data, argc - 2, argv + 2);

	if (strcmp(argv[1], "symbol") == 0)
		return dump_symbol(ccli, data, argc - 2, argv + 2);

	if (strcmp(argv[1], "address") == 0)
		return dump_address(ccli, data, argc - 2, argv + 2);

	return 0;
}

static int dump_section_completion(struct ccli *ccli, void *data,
				   int argc, char **argv,
				   char ***list, int word, char *match)
{
	if (!argc || (argc == 1 && strlen(match)))
		return section_completion(ccli, data, list, word, 0);

	return 0;
}

static int dump_symbol_completion(struct ccli *ccli, void *data,
				  int argc, char **argv,
				  char ***list, int word, char *match)
{
	char **words;

	if (!argc || (argc == 1 && strlen(match)))
		return symbol_completion(ccli, data, list, word);

	if (argc == 1 && !strlen(match)) {
		words = calloc(1, sizeof(*words));
		if (!words)
			return 0;
		words[0] = strdup("-");
		*list = words;
		return 1;
	}

	if (argc == 2 || (argc == 3 && strlen(match))) {
		if (strcmp(argv[1], "-") == 0)
			return symbol_completion(ccli, data, list, word);
	}

	return 0;
}

int dump_completion(struct ccli *ccli, const char *command,
		    const char *line, int word,
		    char *match, char ***list, void *data)
{
	char *types[] = { "section", "symbol", "address" };
	char **words;
	char **argv;
	int argc;
	int ret = 0;
	int i;

	if (word == 1) {
		words = calloc(ARRAY_SIZE(types), sizeof(char *));
		if (!words)
			return 0;
		for (i = 0; i < ARRAY_SIZE(types); i++)
			words[i] = strdup(types[i]);
		*list = words;
		return i;
	}

	argc = ccli_line_parse(line, &argv);
	if (argc < 0)
		return 0;

	if (strcmp(argv[1], "section") == 0)
		ret = dump_section_completion(ccli, data, argc - 2, argv + 2,
					      list, word - 2, match);

	if (strcmp(argv[1], "symbol") == 0)
		ret = dump_symbol_completion(ccli, data, argc - 2, argv + 2,
					list, word - 2, match);

	ccli_argv_free(argv);

	return ret;
}
