# SPDX-License-Identifier: LGPL-2.1

include $(src)/scripts/utils.mk

OBJS =
OBJS += shelf.o
OBJS += list.o
OBJS += dump.o

OBJS := $(OBJS:%.o=$(bdir)/%.o)
DEPS := $(OBJS:$(bdir)/%.o=$(bdir)/.%.d)

$(bdir)/%.o: %.c
	$(Q)$(call do_compile)

$(DEPS): $(bdir)/.%.d: %.c
	$(Q)$(CC) -M -MT $(bdir)/$*.o $(CPPFLAGS) $(CFLAGS) $< > $@

$(OBJS): $(bdir)/%.o : $(bdir)/.%.d

$(OBJS): | $(bdir)
$(DEPS): | $(bdir)

$(bdir)/shelf: $(OBJS)
	$(Q)$(do_app_build)

shelf: $(bdir)/shelf

clean:
	$(Q)$(call do_clean,$(OBJS) .*.d)

dep_includes := $(wildcard $(DEPS))

ifneq ($(dep_includes),)
  include $(dep_includes)
endif

.PHONY: shelf clean
