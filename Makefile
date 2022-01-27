# SPDX-License-Identifier: LGPL-2.1
# shelf version:
SE_VERSION = 0
SE_PATCHLEVEL = 0
SE_EXTRAVERSION = dev
SHELF_VERSION = $(SE_VERSION).$(SE_PATCHLEVEL).$(SE_EXTRAVERSION)

export SE_VERSION
export SE_PATCHLEVEL
export SE_EXTRAVERSION
export SHELF_VERSION

MAKEFLAGS += --no-print-directory

# Makefiles suck: This macro sets a default value of $(2) for the
# variable named by $(1), unless the variable has been set by
# environment or command line. This is necessary for CC and AR
# because make sets default values, so the simpler ?= approach
# won't work as expected.
define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef

# Allow setting CC and AR, or setting CROSS_COMPILE as a prefix.
$(call allow-override,CC,$(CROSS_COMPILE)gcc)
$(call allow-override,AR,$(CROSS_COMPILE)ar)
$(call allow-override,PKG_CONFIG,pkg-config)
$(call allow-override,LD_SO_CONF_PATH,/etc/ld.so.conf.d/)
$(call allow-override,LDCONFIG,ldconfig)

EXT = -std=gnu99
INSTALL = install

# Use DESTDIR for installing into a different root directory.
# This is useful for building a package. The program will be
# installed in this directory as if it was the root directory.
# Then the build tool can move it later.
DESTDIR ?=
DESTDIR_SQ = '$(subst ','\'',$(DESTDIR))'

LP64 := $(shell echo __LP64__ | ${CC} ${CFLAGS} -E -x c - | tail -n 1)
ifeq ($(LP64), 1)
  libdir_relative_temp = lib64
else
  libdir_relative_temp = lib
endif

libdir_relative ?= $(libdir_relative_temp)
prefix ?= /usr/local
man_dir = $(prefix)/share/man
man_dir_SQ = '$(subst ','\'',$(man_dir))'
libdir = $(prefix)/$(libdir_relative)
libdir_SQ = '$(subst ','\'',$(libdir))'
includedir_relative ?= include
includedir = $(prefix)/$(includedir_relative)
includedir_SQ = '$(subst ','\'',$(includedir))'
pkgconfig_dir ?= $(word 1,$(shell $(PKG_CONFIG) 		\
			--variable pc_path pkg-config | tr ":" " "))


etcdir ?= /etc
etcdir_SQ = '$(subst ','\'',$(etcdir))'

export man_dir man_dir_SQ html_install html_install_SQ INSTALL
export img_install img_install_SQ
export DESTDIR DESTDIR_SQ

pound := \#

HELP_DIR = -DHELP_DIR=$(html_install)
HELP_DIR_SQ = '$(subst ','\'',$(HELP_DIR))'
#' emacs highlighting gets confused by the above escaped quote.

BASH_COMPLETE_DIR ?= $(etcdir)/bash_completion.d

# copy a bit from Linux kbuild

ifeq ("$(origin V)", "command line")
  VERBOSE = $(V)
endif
ifndef VERBOSE
  VERBOSE = 0
endif

SILENT := $(if $(findstring s,$(filter-out --%,$(MAKEFLAGS))),1)

LIBCCLI_MIN_VERSION = 1.1

# Test for necessary libraries
TEST_LIBCCLI = $(shell sh -c "$(PKG_CONFIG) --atleast-version $(LIBCCLI_MIN_VERSION) libccli > /dev/null 2>&1 && echo y")

ifeq ("$(TEST_LIBCCLI)", "y")
LIBCCLI_INCLUDES = $(shell sh -c "$(PKG_CONFIG) --cflags libccli")
LIBCCLI_LIBS = $(shell sh -c "$(PKG_CONFIG) --libs libccli")
else
 ifneq ($(MAKECMDGOALS),clean)
   $(error libccli.so minimum version of $(LIBCCLI_MIN_VERSION) not installed)
 endif
endif

# $(call test-build, snippet, ret) -> ret if snippet compiles
#                                  -> empty otherwise
test-build = $(if $(shell sh -c 'echo "$(1)" | \
	$(CC) -o /dev/null -c -x c - > /dev/null 2>&1 && echo y'), $2)

ifeq ("$(origin O)", "command line")

  saved-output := $(O)
  BUILD_OUTPUT := $(shell cd $(O) && /bin/pwd)
  $(if $(BUILD_OUTPUT),, \
    $(error output directory "$(saved-output)" does not exist))

else
  BUILD_OUTPUT = $(CURDIR)
endif

srctree		:= $(if $(BUILD_SRC),$(BUILD_SRC),$(CURDIR))
objtree		:= $(BUILD_OUTPUT)
src		:= $(srctree)
obj		:= $(objtree)
bdir		:= $(obj)/src

export prefix src obj bdir

LIBS =$(LIBCCLI_LIBS)

export LIBS

export Q SILENT VERBOSE EXT

# Include the utils
include scripts/utils.mk

# Set compile option CFLAGS if not set elsewhere
CFLAGS ?= -g -Wall
CPPFLAGS ?=
LDFLAGS ?=

CFLAGS += $(LIBCCLI_INCLUDES)

export CFLAGS
export INCLUDES

# Append required CFLAGS
override CFLAGS += -D_GNU_SOURCE $(INCLUDES)

all: all_cmd

TARGETS = shelf

all_cmd: $(TARGETS)

shelf: force
	make -C src $@

VERSION_FILE = ktest_version.h

VIM_TAGS = $(obj)/tags
EMACS_TAGS = $(obj)/TAGS
CSCOPE_TAGS = $(obj)/cscope

$(VIM_TAGS): force
	$(RM) $@
	$(call find_tag_files) | (cd $(obj) && xargs ctags --extra=+f --c-kinds=+px)

$(EMACS_TAGS): force
	$(RM) $@
	$(call find_tag_files) | (cd $(obj) && xargs etags)

$(CSCOPE_TAGS): force
	$(RM) $(obj)/cscope*
	$(call find_tag_files) | cscope -b -q

tags: $(VIM_TAGS)
TAGS: $(EMACS_TAGS)
cscope: $(CSCOPE_TAGS)

install:

doc:
	$(Q)$(call descend,$(src)/Documentation,all)

doc_clean:
	$(Q)$(call descend,$(src)/Documentation,clean)

install_doc:
	$(Q)$(call descend,$(src)/Documentation,install)

define build_uninstall_script
	$(Q)mkdir $(BUILD_OUTPUT)/tmp_build
	$(Q)$(MAKE) -C $(src) DESTDIR=$(BUILD_OUTPUT)/tmp_build/ O=$(BUILD_OUTPUT) $1 > /dev/null
	$(Q)find $(BUILD_OUTPUT)/tmp_build ! -type d -printf "%P\n" > $(BUILD_OUTPUT)/build_$2
	$(Q)$(RM) -rf $(BUILD_OUTPUT)/tmp_build
endef

build_uninstall: $(BUILD_PREFIX)
	$(call build_uninstall_script,install,uninstall)

$(BUILD_OUTPUT)/build_uninstall: build_uninstall

define uninstall_file
	if [ -f $(DESTDIR)/$1 -o -h $(DESTDIR)/$1 ]; then \
		$(call print_uninstall,$(DESTDIR)/$1)$(RM) $(DESTDIR)/$1; \
	fi;
endef

uninstall: $(BUILD_OUTPUT)/build_uninstall
	@$(foreach file,$(shell cat $(BUILD_OUTPUT)/build_uninstall),$(call uninstall_file,$(file)))

PHONY += force
force:

# Declare the contents of the .PHONY variable as phony.  We keep that
# information in a variable so we can use it in if_changed and friends.
.PHONY: $(PHONY)

OBJS := $(OBJS:%.o=$(bdir)/%.o)
DEPS := $(OBJS:$(bdir)/%.o=$(bdir)/.%.d)

all: $(DEFAULT_TARGET)

$(bdir):
	@mkdir -p $(bdir)

VERSION = $(KT_VERSION)
PATCHLEVEL = $(KT_PATCHLEVEL)
EXTRAVERSION = $(KT_EXTRAVERSION)

define make_version.h
  (echo '/* This file is automatically generated. Do not modify. */';		\
   echo \#define VERSION_CODE $(shell						\
   expr $(VERSION) \* 256 + $(PATCHLEVEL));					\
   echo '#define EXTRAVERSION ' $(EXTRAVERSION);				\
   echo '#define VERSION_STRING "'$(VERSION).$(PATCHLEVEL).$(EXTRAVERSION)'"';	\
  ) > $1
endef

define update_version.h
  ($(call make_version.h, $@.tmp);		\
    if [ -r $@ ] && cmp -s $@ $@.tmp; then	\
      rm -f $@.tmp;				\
    else					\
      echo '  UPDATE             $@';		\
      mv -f $@.tmp $@;				\
    fi);
endef

$(VERSION_FILE): force
	$(Q)$(call update_version.h)

clean:
	$(Q)$(call descend_clean,src)
	$(Q)$(call do_clean, \
	  $(TARGETS) $(bdir)/*.a $(bdir)/*.so $(bdir)/*.so.* $(bdir)/*.o $(bdir)/.*.d \
	  $(VERSION_FILE))

.PHONY: clean
