GCC = gcc

INCLUDE = -Isrc/include
CFLAGS = -Wall -Werror -c $(INCLUDE) -MMD -MF $(DEPDIR)/$*.d
LDFLAGS = -lp11 -lcrypto

DEPDIR = .deps/


SOURCE = $(wildcard src/*.c) \
         $(wildcard src/*/*.c)

OBJECTS = $(patsubst %.c,%.o,$(SOURCE))

DEPENDS = $(patsubst %.c,$(DEPDIR)/%.d,$(SOURCE))


all: sed-tools

%.d:
	@mkdir -p $(@D)

%.o: %.c Makefile
	$(GCC) $(CFLAGS) -o $@ $<

sed-tools: $(OBJECTS)
	$(GCC) $(LDFLAGS) -o $@ $(OBJECTS)

.PHONY: install
install:
	@echo "TODO"

.PHONY: uninstall
uninstall:
	@echo "TODO"

.PHONY: clean
clean:
	rm -rf $(DEPDIR) $(OBJECTS)


include $(DEPENDS)
