AUTOMAKE_OPTIONS = foreign

noinst_DATA = \
	flowtable_afxdp.o \
	xdp_noop.o

sources = \
	flowtable_afxdp.c \
	xdp_noop.c

EXTRA_DIST = \
	$(sources) \
	bpf_compiler.h \
	bpf_miniflow.h \
	bpf_netlink.h \
	bpf_workaround.h

# The following is based on commands for the Automake "distdir" target.
distfiles: Makefile
	@srcdirstrip=`echo "$(srcdir)" | sed 's/[].[^$$\\*]/\\\\&/g'`; \
	topsrcdirstrip=`echo "$(top_srcdir)" | sed 's/[].[^$$\\*]/\\\\&/g'`; \
	list='$(DISTFILES)'; \
	for file in $$list; do echo $$file; done | \
	  sed -e "s|^$$srcdirstrip/||;t" \
	      -e "s|^$$topsrcdirstrip/|$(top_builddir)/|;t" | \
	  LC_ALL=C sort -u > $@
CLEANFILES = distfiles

depdir := .deps
DEPFLAGS = -MT $*.o -MMD -MP -MF $(depdir)/$*.d

$(depdir): ; @mkdir -p $@

clean-local:
	-rm -rf $(depdir)

CLANG ?= clang
LLC ?= llc

AM_CPPFLAGS = -I $(top_srcdir)/include
AM_CPPFLAGS += -I $(top_builddir)/include
AM_CPPFLAGS += -I $(top_srcdir)/lib
AM_CPPFLAGS += -I $(top_builddir)/lib

AM_CFLAGS = -Wall
AM_CFLAGS += -Wextra
AM_CFLAGS += -Wno-sign-compare
AM_CFLAGS += -Wformat -Wformat-security
AM_CFLAGS += -Wswitch-enum
AM_CFLAGS += -Wunused-parameter
AM_CFLAGS += -Wbad-function-cast
AM_CFLAGS += -Wcast-align
AM_CFLAGS += -Wstrict-prototypes
AM_CFLAGS += -Wold-style-definition
AM_CFLAGS += -Wmissing-field-initializers
AM_CFLAGS += -fno-strict-aliasing
AM_CFLAGS += -Wswitch-bool
AM_CFLAGS += -Wlogical-not-parentheses
AM_CFLAGS += -Wsizeof-array-argument
AM_CFLAGS += -Wshift-negative-value
AM_CFLAGS += -Wshadow
AM_CFLAGS += -Wcast-align
AM_CFLAGS += -Wno-unused-value
AM_CFLAGS += -Wno-compare-distinct-pointer-types
AM_CFLAGS += -O2

%.o: %.c

SUFFIXES+ = .ll
# Remove BTF for xdp_noop so that ip command can attach the program
%.ll: %.c $(depdir)/%.d | $(depdir)
	$(CLANG) $(DEPFLAGS) $(AM_CPPFLAGS) $(AM_CFLAGS) \
		$(if $(subst xdp_noop,,$*),-g,) -S \
		-target bpf -emit-llvm -c $< -o $@
CLEANFILES += *.ll

%.o: %.ll
	$(LLC) -march=bpf $(LLC_FLAGS) -filetype=obj -o $@ $<
CLEANFILES += *.o

depfiles := $(sources:%.c=$(depdir)/%.d)
$(depfiles):
include $(wildcard $(depfiles))
