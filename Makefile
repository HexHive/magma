CBDIR := $(abspath codebase)
TMPDIR := $(abspath tmp)
PATCHDIR := $(abspath patches)
BINDIR := $(abspath build)
export BINDIR

BUG_PATCHES := $(addprefix bugs/,$(notdir $(wildcard $(PATCHDIR)/bugs/*.patch)))
SETUP_PATCHES := $(addprefix setup/,$(notdir $(wildcard $(PATCHDIR)/setup/*.patch)))
PATCHES := $(SETUP_PATCHES) $(BUG_PATCHES)
TARGETS := $(shell find $(CBDIR) -maxdepth 1 -type d -printf %P\\n)

BUG_COUNT := $(shell echo $(lastword $(sort $(patsubst bugs/%.patch,%,$(BUG_PATCHES)))) | sed 's/^0*//')
export BUG_COUNT

.PHONY: all clean patch copy $(PATCHES) $(TARGETS)

.NOTPARALLEL:

all: $(PATCHES) $(TARGETS)
	@rm -r $(TMPDIR)

clean:
	rm -rf tmp build/*

patch: $(PATCHES)

copy:
	@echo "Copying codebase to tmp directory"
	@if [ -d "$(TMPDIR)" ]; then \
		rm -r "$(TMPDIR)"; \
	fi;
	@cp -r "$(CBDIR)" "$(TMPDIR)"

$(PATCHES): copy
	@echo "Applying patch $(basename $@)"
	@sed -- 's/$(notdir $(CBDIR))/$(notdir $(TMPDIR))/g' $(PATCHDIR)/$@ | git apply

$(TARGETS): copy patch
	@mkdir -p $(BINDIR)
	@echo "Building $@"
	@cd $(TMPDIR); $(MAKE) $@;
