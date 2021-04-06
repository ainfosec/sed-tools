GCC = gcc

INCLUDE = -Isrc/include
CFLAGS = -Wall -Werror -c $(INCLUDE) -MMD -MF $(DEPDIR)/$*.d
LDFLAGS = -lp11 -lcrypto

DEPDIR = .deps/


SOURCE = $(wildcard src/*.c) \
         $(wildcard src/*/*.c)

OBJECTS = $(patsubst %.c,%.o,$(SOURCE))

DEPENDS = $(patsubst %.c,$(DEPDIR)/%.d,$(SOURCE))

ifeq ($(PREFIX),)
    PREFIX := /usr
endif

all: sed-tools

%.d:
	@mkdir -p $(@D)

%.o: %.c Makefile
	$(GCC) $(CFLAGS) -o $@ $<

sed-tools: $(OBJECTS)
	$(GCC) -o $@ $(OBJECTS) $(LDFLAGS)

.PHONY: install
install: sed-tools
	install -d $(DESTDIR)/$(PREFIX)/bin
	install -m 755 sed-tools $(DESTDIR)/$(PREFIX)/bin

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)/$(PREFIX)/bin/sed-tools

.PHONY: clean
clean:
	rm -rf $(DEPDIR) $(OBJECTS) sed-tools


include $(DEPENDS)
