// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Google Inc, Steven Rostedt <rostedt@goodmis.org>
 */
#include <regex.h>
#include "shelf.h"

static void list_usage(struct ccli *ccli)
{
	ccli_printf(ccli, "usage: list <type>\n"
		    "  <type> : sections\n");
}

static int show_section(struct ccli *ccli, struct shelf *shelf, int i, int line,
			regex_t *preg)
{
	union Elf_Shdr *shdr;
	uint64_t flags;
	uint64_t addr;
	uint64_t size;
	uint32_t type;
	const char *name;
	int c;

	shdr = get_shdr(shelf, i);
	if (!shdr)
		return -1;

	name = shdr_name(shelf, shdr);

	if (preg && !regexec(preg, name, 0, NULL, 0) == 0)
		return line;

	type = shdr_type(shelf, shdr);
	flags = shdr_flags(shelf, shdr);

	line = ccli_page(ccli, line, "%s:%*s", name, (int)(30 - strlen(name)), "");
	if (line < 0)
		return -1;

	size = shdr_size(shelf, shdr);
	ccli_printf(ccli, "%zd\t", size);

	switch (type) {
	case SHT_NULL:
		ccli_printf(ccli, "NULL   ");
		break;
	case SHT_PROGBITS:
		ccli_printf(ccli, "PROGBITS");
		break;
	case SHT_SYMTAB:
		ccli_printf(ccli, "SYMTAB  ");
		break;
	case SHT_STRTAB:
		ccli_printf(ccli, "STRTAB  ");
		break;
	case SHT_RELA:
		ccli_printf(ccli, "RELA    ");
		break;
	case SHT_HASH:
		ccli_printf(ccli, "HASH    ");
		break;
	case SHT_DYNAMIC:
		ccli_printf(ccli, "DYNAMIC ");
		break;
	case SHT_NOTE:
		ccli_printf(ccli, "NOTE    ");
		break;
	case SHT_NOBITS:
		ccli_printf(ccli, "NOBITS  ");
		break;
	case SHT_REL:
		ccli_printf(ccli, "REL     ");
		break;
	case SHT_SHLIB:
		ccli_printf(ccli, "SHLIB   ");
		break;
	case SHT_DYNSYM:
		ccli_printf(ccli, "DYNSYM  ");
		break;
	case SHT_LOPROC:
		ccli_printf(ccli, "LOPROC  ");
		break;
	case SHT_HIPROC:
		ccli_printf(ccli, "HIPROC  ");
		break;
	case SHT_LOUSER:
		ccli_printf(ccli, "LOUSER  ");
		break;
	case SHT_HIUSER:
		ccli_printf(ccli, "HIUSER  ");
		break;
	}

	ccli_printf(ccli, "     ");

	c = 0;

	if (flags & SHF_WRITE)
		c += ccli_printf(ccli, "W");

	if (flags & SHF_ALLOC)
		c += ccli_printf(ccli,"%sA", flags & SHF_WRITE ? "|" : "");

	if (flags & SHF_EXECINSTR)
		c += ccli_printf(ccli,"%sX", flags & (SHF_WRITE|SHF_ALLOC) ? "|" : "");

	addr = shdr_addr(shelf, shdr);

	ccli_printf(ccli, "%*zx", 24 - c, addr);

	ccli_printf(ccli, "\n");

	return line;
}

static regex_t *get_regex(regex_t *preg, struct ccli *ccli, const char *str)
{
	int ret;

	ret = regcomp(preg, str, REG_ICASE|REG_NOSUB);
	if (ret < 0) {
		ccli_printf(ccli, "\nInvalid regex %s\n", str);
		return NULL;
	}
	return preg;
}

static int list_sections(struct ccli *ccli, void *data,
			int argc, char **argv)
{
	struct shelf *shelf = data;
	regex_t *preg = NULL;
	regex_t reg;
	int line = 1;
	int i;

	if (argc > 0) {
		preg = get_regex(&reg, ccli, argv[0]);
		if (!preg)
			return 0;
	}

	for (i = 0; line >= 0 && i < shelf->shnum; i++)
		line = show_section(ccli, shelf, i, line, preg);

	if (preg)
		regfree(preg);

	return 0;
}

static int show_symbol(struct ccli *ccli, struct shelf *shelf, int i, int line,
		       regex_t *preg)
{
	union Elf_Sym *sym;
	union Elf_Shdr *shdr;
	const char *name;
	unsigned char info;
	uint16_t shndx;
	uint64_t value;

	sym = get_sym(shelf, i);
	if (!sym)
		return -1;

	name = sym_name(shelf, sym);
	if (!name)
		return line;

	if (preg && !regexec(preg, name, 0, NULL, 0) == 0)
		return line;

	line = ccli_page(ccli, line, "%s:%*s", name, (int)(30 - strlen(name)), "");
	if (line < 0)
		return -1;

	info = sym_info_type(shelf, sym);
	switch (info) {
	case STT_NOTYPE:
		break;
	case STT_OBJECT:
		ccli_printf(ccli, "OBJECT");
		break;
	case STT_FUNC:
		ccli_printf(ccli, "FUNC");
		break;
	case STT_SECTION:
		ccli_printf(ccli, "SECTION");
		break;
	case STT_FILE:
		ccli_printf(ccli, "FILE");
		break;
	case STT_LOPROC:
		ccli_printf(ccli, "LOPROC");
		break;
	case STT_HIPROC:
		ccli_printf(ccli, "HIPROC");
		break;
	}

	ccli_printf(ccli, "\t");

	info = sym_info_bind(shelf, sym);

	switch (info) {
	case STB_LOCAL:
		ccli_printf(ccli, "LOCAL");
		break;
	case STB_GLOBAL:
		ccli_printf(ccli, "GLOBAL");
		break;
	case STB_WEAK:
		ccli_printf(ccli, "WEAK");
		break;
	case STB_LOPROC:
		ccli_printf(ccli, "LOPROC");
		break;
	case STB_HIPROC:
		ccli_printf(ccli, "HIPROC");
		break;
	}

	value = sym_value(shelf, sym);
	ccli_printf(ccli, "\t%zx", value);

	shndx = sym_shndx(shelf, sym);
	shdr = get_shdr(shelf, shndx);
	if (shdr) {
		const char *name = shdr_name(shelf, shdr);

		ccli_printf(ccli, "\t(%s)", name);
	}
	ccli_printf(ccli, "\n");

	return line;
}

static int list_symbols(struct ccli *ccli, void *data,
			int argc, char **argv)
{
	struct shelf *shelf = data;
	regex_t *preg = NULL;
	regex_t reg;
	int line = 1;
	int i;

	if (argc > 0) {
		preg = get_regex(&reg, ccli, argv[0]);
		if (!preg)
			return 0;
	}

	for (i = 0; line >= 0 && i < shelf->symnum; i++)
		line = show_symbol(ccli, shelf, i, line, preg);

	if (preg)
		regfree(preg);

	return 0;
}

static void print_rel_section(struct ccli *ccli, struct shelf *shelf,
			      const char *name, uint64_t offset)
{
	union Elf_Shdr *shdr;
	uint64_t addr;

	if (!name)
		name = "";

	ccli_printf(ccli, "\t%s%*s", name, (int)(26 - strlen(name)), "");

	shdr = find_section(shelf, offset);
	if (!shdr)
		return;

	addr = shdr_addr(shelf, shdr);
	name = shdr_name(shelf, shdr);
	if (name)
		ccli_printf(ccli, "\t%s", name);
	offset -= addr;
	if (offset > shdr_size(shelf, shdr))
		return;

	addr = shdr_offset(shelf, shdr);
	addr += offset;
	if (shelf->sixtyfour)
		ccli_printf(ccli, "\t%16zx", read_offset(shelf, addr));
	else
		ccli_printf(ccli, "\t%8zx", read_offset(shelf, addr));
}

static int do_rel_section(struct ccli *ccli, struct shelf *shelf, int s, int line,
			  uint32_t reltype, off_t *paddr, uint64_t *pnum,
			  uint64_t *pentsize, regex_t *preg)
{
	union Elf_Shdr *shdr;
	const char *name;
	uint64_t size;
	uint64_t entsize;
	uint64_t num;
	uint32_t type;

	shdr = get_shdr(shelf, s);
	if (!shdr)
		return -1;

	type = shdr_type(shelf, shdr);
	if (type != reltype)
		return line;

	name = shdr_name(shelf, shdr);

	if (preg && !regexec(preg, name, 0, NULL, 0) == 0)
		return line;

	if (line == 1) {
		line = ccli_page(ccli, line, " Section name                          Size         Elements\n");
		line = ccli_page(ccli, line, " ------------                          ----         --------\n");
	}

	line = ccli_page(ccli, line, "%s:%*s", name, (int)(30 - strlen(name)), "");
	if (line < 0)
		return -1;

	size = shdr_size(shelf, shdr);
	entsize = shdr_entsize(shelf, shdr);

	num = entsize ? size / entsize : 1;

	ccli_printf(ccli, "%12zd\t%12zd", size, num);

	ccli_printf(ccli, "\n");

	*paddr = shdr_offset(shelf, shdr);
	*pnum = num;
	*pentsize = entsize;

	return line;
}

static int show_rel_entry(struct ccli *ccli, struct shelf *shelf,
			  union Elf_Rel *rel, int line, regex_t *preg,
			  bool *first)
{
	union Elf_Sym *sym;
	const char *name = NULL;
	uint64_t offset;
	uint64_t type;
	uint64_t symidx;

	offset = rel_offset(shelf, rel);
	type = rel_info_type(shelf, rel);
	symidx = rel_info_sym(shelf, rel);

	sym = get_sym(shelf, symidx);
	if (preg && !sym)
		return line;

	if (sym) {
		name = sym_name(shelf, sym);
		if (preg && !regexec(preg, name, 0, NULL, 0) == 0)
			return line;
	}

	if (*first) {
		*first = false;
		line = ccli_page(ccli, line, "       offset              type      sym idx\t  symbol name\n");
		if (line < 0)
			return -1;
		line = ccli_page(ccli, line, "       ------              ----      -------\t  -----------\n");
		if (line < 0)
			return -1;
	}

	line = ccli_page(ccli, line, "  %12zx  %6zd %12zd",
			 offset, type, symidx);
	if (line < 0)
		return -1;

	print_rel_section(ccli, shelf, name, offset);

	ccli_printf(ccli, "\n");

	return line;
}

static int show_rel_section(struct ccli *ccli, struct shelf *shelf, int s, int line,
			    regex_t *preg, regex_t *pregsym)
{
	uint64_t entsize;
	uint64_t num;
	off_t addr;
	bool first = true;
	int orig_line = line;
	int i;

	line = do_rel_section(ccli, shelf, s, line, SHT_REL, &addr, &num, &entsize, preg);
	if (line < 0)
		return -1;

	/* If our section is not found */
	if (orig_line == line)
		return line;

	if (!preg)
		return line;

	for (i = 0; line >= 0 && i < num; i++) {
		union Elf_Rel *rel;

		rel = shelf->map + addr + (i * entsize);
		line = show_rel_entry(ccli, shelf, rel, line, pregsym, &first);
	}

	return line;
}

static int list_rels(struct ccli *ccli, void *data,
		     int argc, char **argv)
{
	struct shelf *shelf = data;
	regex_t *pregsym = NULL;
	regex_t *preg = NULL;
	regex_t regsym;
	regex_t reg;
	bool found = false;
	int line = 1;
	int i;

	if (argc > 0) {
		preg = get_regex(&reg, ccli, argv[0]);
		if (!preg)
			return 0;
	}

	if (argc > 1) {
		pregsym = get_regex(&regsym, ccli, argv[1]);
		if(!pregsym)
			goto out;
	}

	for (i = 0; line >= 0 && i < shelf->shnum; i++) {
		line = show_rel_section(ccli, shelf, i, line, preg, pregsym);
		if (line != 1)
			found = true;
	}

	if (!preg && !found)
		ccli_printf(ccli, "No REL type sections found\n");

 out:
	if (preg)
		regfree(preg);

	return 0;
}

static int show_rela_entry(struct ccli *ccli, struct shelf *shelf,
			   union Elf_Rela *rel, int line, regex_t *preg,
			   bool *first)
{
	union Elf_Sym *sym;
	const char *name = NULL;
	uint64_t offset;
	uint64_t type;
	uint64_t symidx;
	int64_t addend;

	offset = rela_offset(shelf, rel);
	type = rela_info_type(shelf, rel);
	symidx = rela_info_sym(shelf, rel);
	addend = rela_addend(shelf, rel);

	sym = get_sym(shelf, symidx);
	if (preg && !sym)
		return line;

	if (sym) {
		name = sym_name(shelf, sym);
		if (preg && !regexec(preg, name, 0, NULL, 0) == 0)
			return line;
	}

	if (*first) {
		*first = false;
		line = ccli_page(ccli, line, "       offset              addend    type      sym idx\t  symbol name\n");
		if (line < 0)
			return -1;
		line = ccli_page(ccli, line, "       ------              ------    ----      -------\t  -----------\n");
		if (line < 0)
			return -1;
	}

	line = ccli_page(ccli, line, "  %12zx (%12zd)  %6zd %12zd",
			 offset, addend, type, symidx);
	if (line < 0)
		return -1;

	print_rel_section(ccli, shelf, name, offset);

	ccli_printf(ccli, "\n");
	return line;
}

static int show_rela_section(struct ccli *ccli, struct shelf *shelf, int s, int line,
			    regex_t *preg, regex_t *pregsym)
{
	uint64_t entsize;
	uint64_t num;
	off_t addr;
	bool first = true;
	int orig_line = line;
	int i;

	line = do_rel_section(ccli, shelf, s, line, SHT_RELA, &addr, &num, &entsize, preg);
	if (line < 0)
		return -1;

	/* If our section is not found */
	if (orig_line == line)
		return line;

	if (!preg)
		return line;

	for (i = 0; line >= 0 && i < num; i++) {
		union Elf_Rela *rela;

		rela = shelf->map + addr + (i * entsize);
		line = show_rela_entry(ccli, shelf, rela, line, pregsym, &first);
	}

	return line;
}

static int list_relas(struct ccli *ccli, void *data,
		      int argc, char **argv)
{
	struct shelf *shelf = data;
	regex_t *pregsym = NULL;
	regex_t *preg = NULL;
	regex_t regsym;
	regex_t reg;
	bool found = false;
	int line = 1;
	int i;

	if (argc > 0) {
		preg = get_regex(&reg, ccli, argv[0]);
		if (!preg)
			return 0;
	}

	if (argc > 1) {
		pregsym = get_regex(&regsym, ccli, argv[1]);
		if(!pregsym)
			goto out;
	}

	for (i = 0; line >= 0 && i < shelf->shnum; i++) {
		line = show_rela_section(ccli, shelf, i, line, preg, pregsym);
		if (line != 1)
			found = true;
	}

	if (!preg && !found)
		ccli_printf(ccli, "No RELA type sections found\n");

 out:
	if (preg)
		regfree(preg);

	return 0;
}

int list_cmd(struct ccli *ccli, const char *command, const char *line,
	     void *data, int argc, char **argv)
{
	if (argc < 2) {
		list_usage(ccli);
		return 0;
	}

	if (strcmp(argv[1], "sections") == 0)
		return list_sections(ccli, data, argc - 2, argv + 2);

	if (strcmp(argv[1], "symbols") == 0)
		return list_symbols(ccli, data, argc - 2, argv + 2);

	if (strcmp(argv[1], "rel") == 0)
		return list_rels(ccli, data, argc - 2, argv + 2);

	if (strcmp(argv[1], "rela") == 0)
		return list_relas(ccli, data, argc - 2, argv + 2);

	return 0;
}

static int list_section_completion(struct ccli *ccli, void *data,
				   int argc, char **argv,
				   char ***list, int word, char *match)
{
	if (!argc || (argc == 1 && strlen(match)))
		return section_completion(ccli, data, list, word, 0);

	return 0;
}

static int list_symbol_completion(struct ccli *ccli, void *data,
				  int argc, char **argv,
				  char ***list, int word, char *match)
{
	if (!argc || (argc == 1 && strlen(match)))
		return symbol_completion(ccli, data, list, word);

	return 0;
}

static int rel_completion(struct ccli *ccli, void *data,
			  int argc, char **argv,
			  char ***list, int word, char *match,
			  uint32_t type)
{
	if (!argc || (argc == 1 && strlen(match)))
		return section_completion(ccli, data, list, word, type);
	return 0;
}

static int list_rel_completion(struct ccli *ccli, void *data,
			       int argc, char **argv,
			       char ***list, int word, char *match)
{
	return rel_completion(ccli, data, argc, argv, list, word, match, SHT_REL);
}

static int list_rela_completion(struct ccli *ccli, void *data,
				int argc, char **argv,
				char ***list, int word, char *match)
{
	return rel_completion(ccli, data, argc, argv, list, word, match, SHT_RELA);
}

int list_completion(struct ccli *ccli, const char *command,
		    const char *line, int word,
		    char *match, char ***list, void *data)
{
	char *types[] = { "sections", "symbols", "rel", "rela" };
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

	if (strcmp(argv[1], "sections") == 0)
		ret = list_section_completion(ccli, data, argc - 2, argv + 2,
					      list, word - 2, match);

	if (strcmp(argv[1], "symbols") == 0)
		ret = list_symbol_completion(ccli, data, argc - 2, argv + 2,
					     list, word - 2, match);

	if (strcmp(argv[1], "rel") == 0)
		ret = list_rel_completion(ccli, data, argc - 2, argv + 2,
					  list, word - 2, match);

	if (strcmp(argv[1], "rela") == 0)
		ret = list_rela_completion(ccli, data, argc - 2, argv + 2,
					   list, word - 2, match);

	ccli_argv_free(argv);

	return ret;
}
