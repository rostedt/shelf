/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SHELF__H
#define __SHELF__H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ccli.h>
#include <elf.h>

union Elf_Ehdr {
	Elf32_Ehdr		h32;
	Elf64_Ehdr		h64;
};

union Elf_Shdr {
	Elf32_Shdr		h32;
	Elf64_Shdr		h64;
};

union Elf_Sym {
	Elf32_Sym		h32;
	Elf64_Sym		h64;
};

union Elf_Rel {
	Elf32_Rel		h32;
	Elf64_Rel		h64;
};

union Elf_Rela {
	Elf32_Rela		h32;
	Elf64_Rela		h64;
};

enum endian {
	ENDIAN_SAME,		/* file and machine match */
	ENDIAN_LITTLE,		/* file little, machine is big */
	ENDIAN_BIG,		/* file big, machine is little */
};

struct shelf {
	char			*file;
	void			*map;
	off_t			phoff;
	off_t			shoff;
	off_t			size;
	off_t			symoff;
	char			*strings;
	char			*shstrings;
	uint64_t		strsize;
	uint64_t		symsize;
	uint64_t		symentsize;
	uint64_t		symnum;
	uint16_t		shentsize;
	uint16_t		shnum;
	uint16_t		fileshnum; // # of entries in shdrs
	union Elf_Ehdr		*ehdr;
	union Elf_Shdr		**shdrs; // addr sorted of file sections
	enum endian		endian;
	bool			sixtyfour;
	int			fd;
};

static inline uint16_t swap16(struct shelf *shelf, uint16_t val)
{
	if (!shelf->endian)
		return val;

	return (val & 0xff) << 8 |
		(val & 0xff00) >> 8;
}

static inline uint32_t swap32(struct shelf *shelf, uint32_t val)
{
	if (!shelf->endian)
		return val;

	return (val & 0xff) << 24 |
		(val & 0xff00) << 8 |
		(val & 0xff0000) >> 8 |
		(val & 0xff000000) >> 24;
}

static inline uint64_t swap64(struct shelf *shelf, uint64_t val)
{
	if (!shelf->endian)
		return val;

	return (val & 0xff) << 56 |
		(val & 0xff00) << 40 |
		(val & 0xff0000) << 24 |
		(val & 0xff000000) << 8 |
		(val & 0xff00000000ULL) >> 8 |
		(val & 0xff0000000000ULL) >> 24 |
		(val & 0xff000000000000ULL) >> 40 |
		(val & 0xff00000000000000ULL) >> 56;
}

static inline uint64_t read_offset(struct shelf *shelf, uint64_t addr)
{
	void *ptr = shelf->map + addr;

	if (addr > shelf->size)
		return 0;

	if (shelf->sixtyfour)
		return swap64(shelf, *(uint64_t *)ptr);
	else
		return swap32(shelf, *(uint32_t *)ptr);
}

static inline uint64_t ehdr_shoff(struct shelf *shelf)
{
	if (shelf->sixtyfour)
		return swap64(shelf, shelf->ehdr->h64.e_shoff);
	else
		return swap32(shelf, shelf->ehdr->h32.e_shoff);
}

static inline uint16_t ehdr_shentsize(struct shelf *shelf)
{
	if (shelf->sixtyfour)
		return swap16(shelf, shelf->ehdr->h64.e_shentsize);
	else
		return swap16(shelf, shelf->ehdr->h32.e_shentsize);
}

static inline uint16_t ehdr_shnum(struct shelf *shelf)
{
	if (shelf->sixtyfour)
		return swap16(shelf, shelf->ehdr->h64.e_shnum);
	else
		return swap16(shelf, shelf->ehdr->h32.e_shnum);
}

static inline uint16_t ehdr_shstrndx(struct shelf *shelf)
{
	if (shelf->sixtyfour)
		return swap16(shelf, shelf->ehdr->h64.e_shstrndx);
	else
		return swap16(shelf, shelf->ehdr->h32.e_shstrndx);
}

static inline const char *shdr_name(struct shelf *shelf, union Elf_Shdr *shdr)
{
	uint32_t nidx;

	if (shelf->sixtyfour)
		nidx = swap32(shelf, shdr->h64.sh_name);
	else
		nidx = swap32(shelf, shdr->h32.sh_name);

	return shelf->shstrings + nidx;
}

static inline uint64_t shdr_offset(struct shelf *shelf, union Elf_Shdr *shdr)
{
	if (shelf->sixtyfour)
		return swap64(shelf, shdr->h64.sh_offset);
	else
		return swap32(shelf, shdr->h32.sh_offset);
}

static inline uint64_t shdr_size(struct shelf *shelf, const union Elf_Shdr *shdr)
{
	if (shelf->sixtyfour)
		return swap64(shelf, shdr->h64.sh_size);
	else
		return swap32(shelf, shdr->h32.sh_size);
}

static inline uint64_t shdr_entsize(struct shelf *shelf, union Elf_Shdr *shdr)
{
	if (shelf->sixtyfour)
		return swap64(shelf, shdr->h64.sh_entsize);
	else
		return swap32(shelf, shdr->h32.sh_entsize);
}

static inline uint32_t shdr_type(struct shelf *shelf, union Elf_Shdr *shdr)
{
	if (shelf->sixtyfour)
		return swap32(shelf, shdr->h64.sh_type);
	else
		return swap32(shelf, shdr->h32.sh_type);
}

static inline uint64_t shdr_flags(struct shelf *shelf, union Elf_Shdr *shdr)
{
	if (shelf->sixtyfour)
		return swap64(shelf, shdr->h64.sh_flags);
	else
		return swap32(shelf, shdr->h32.sh_flags);
}

static inline uint64_t shdr_addr(struct shelf *shelf, const union Elf_Shdr *shdr)
{
	if (shelf->sixtyfour)
		return swap64(shelf, shdr->h64.sh_addr);
	else
		return swap32(shelf, shdr->h32.sh_addr);
}

static inline union Elf_Shdr *get_shdr(struct shelf *shelf, int idx)
{
	if (idx >= shelf->shnum)
		return NULL;

	return shelf->map + shelf->shoff + (shelf->shentsize * idx);
}

static inline union Elf_Sym *get_sym(struct shelf *shelf, int idx)
{
	if (idx >= shelf->symnum)
		return NULL;

	return shelf->map + shelf->symoff + (shelf->symentsize * idx);
}

static inline const char *sym_name(struct shelf *shelf, union Elf_Sym *sym)
{
	uint32_t nidx;

	if (shelf->sixtyfour)
		nidx = swap32(shelf, sym->h64.st_name);
	else
		nidx = swap32(shelf, sym->h32.st_name);

	if (nidx > shelf->strsize)
		return NULL;

	return shelf->strings + nidx;
}

static inline unsigned char sym_info_type(struct shelf *shelf, union Elf_Sym *sym)
{
	if (shelf->sixtyfour)
		return ELF64_ST_TYPE(sym->h64.st_info);
	else
		return ELF32_ST_TYPE(sym->h32.st_info);
}

static inline unsigned char sym_info_bind(struct shelf *shelf, union Elf_Sym *sym)
{
	if (shelf->sixtyfour)
		return ELF64_ST_BIND(sym->h64.st_info);
	else
		return ELF32_ST_BIND(sym->h32.st_info);
}

static inline uint16_t sym_shndx(struct shelf *shelf, union Elf_Sym *sym)
{
	if (shelf->sixtyfour)
		return swap16(shelf, sym->h64.st_shndx);
	else
		return swap16(shelf, sym->h32.st_shndx);
}

static inline uint64_t sym_value(struct shelf *shelf, union Elf_Sym *sym)
{
	if (shelf->sixtyfour)
		return swap64(shelf, sym->h64.st_value);
	else
		return swap32(shelf, sym->h32.st_value);
}

static inline uint64_t rel_offset(struct shelf *shelf, union Elf_Rel *rel)
{
	if (shelf->sixtyfour)
		return swap64(shelf, rel->h64.r_offset);
	else
		return swap32(shelf, rel->h32.r_offset);
}

static inline uint64_t rel_info_type(struct shelf *shelf, union Elf_Rel *rel)
{
	if (shelf->sixtyfour)
		return ELF64_R_TYPE(swap64(shelf, rel->h64.r_info));
	else
		return ELF32_R_TYPE(swap32(shelf, rel->h32.r_info));
}

static inline uint64_t rel_info_sym(struct shelf *shelf, union Elf_Rel *rel)
{
	if (shelf->sixtyfour)
		return ELF64_R_SYM(swap64(shelf, rel->h64.r_info));
	else
		return ELF32_R_SYM(swap32(shelf, rel->h32.r_info));
}

static inline uint64_t rela_offset(struct shelf *shelf, union Elf_Rela *rel)
{
	if (shelf->sixtyfour)
		return swap64(shelf, rel->h64.r_offset);
	else
		return swap32(shelf, rel->h32.r_offset);
}

static inline uint64_t rela_info_type(struct shelf *shelf, union Elf_Rela *rel)
{
	if (shelf->sixtyfour)
		return ELF64_R_TYPE(swap64(shelf, rel->h64.r_info));
	else
		return ELF32_R_TYPE(swap32(shelf, rel->h32.r_info));
}

static inline uint64_t rela_info_sym(struct shelf *shelf, union Elf_Rela *rel)
{
	if (shelf->sixtyfour)
		return ELF64_R_SYM(swap64(shelf, rel->h64.r_info));
	else
		return ELF32_R_SYM(swap32(shelf, rel->h32.r_info));
}

static inline uint64_t rela_addend(struct shelf *shelf, union Elf_Rela *rel)
{
	if (shelf->sixtyfour)
		return swap64(shelf, rel->h64.r_addend);
	else
		return swap32(shelf, rel->h32.r_addend);
}

#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

int list_completion(struct ccli *ccli, const char *command,
		    const char *line, int word,
		    char *match, char ***list, void *data);
int list_cmd(struct ccli *ccli, const char *command, const char *line,
	     void *data, int argc, char **argv);

int dump_cmd(struct ccli *ccli, const char *command, const char *line,
	     void *data, int argc, char **argv);
int dump_completion(struct ccli *ccli, const char *command,
		    const char *line, int word,
		    char *match, char ***list, void *data);

int section_completion(struct ccli *ccli, struct shelf *shelf,
		       char ***list, int word, uint32_t type);
int symbol_completion(struct ccli *ccli, struct shelf *shelf,
		      char ***list, int word);

union Elf_Shdr *find_section(struct shelf *shelf, uint64_t addr);

#endif
