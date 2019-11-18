CFLAGS := -std=c11 -g -O0 -D_POSIX_C_SOURCE=200112L $(CFLAGS)
CXXFLAGS := -std=c++14 -g -O0 $(CXXFLAGS)

DIRS := $(notdir $(shell find . -mindepth 1 -maxdepth 1 -type d))
MAGMA_DIR := $(shell pwd)/magma
MAGMA_LOG := -D'MAGMA_LOG(b,c)=do{magma_log((b),(int)(c));}while(0)' -DMAGMA_ENABLE_CANARIES
MAGMA_CFLAGS := -I$(MAGMA_DIR) -include "$(MAGMA_DIR)/canary.h"
MAGMA_CXXFLAGS := -I$(MAGMA_DIR) -include "$(MAGMA_DIR)/canary.h"
MAGMA_LDFLAGS := -L$(MAGMA_DIR)
MAGMA_LIBS := -l:canary.o -lrt

HOST ?= x86_64
MAGMA_STORAGE ?= MAGMA3

ifdef MAGMA_ISAN
	CFLAGS := $(CFLAGS) -DMAGMA_FATAL_CANARIES
	CXXFLAGS := $(CXXFLAGS) -DMAGMA_FATAL_CANARIES
endif

ifdef MAGMA_HARDEN
	CFLAGS := $(CFLAGS) -DMAGMA_HARDEN_CANARIES
	CXXFLAGS := $(CXXFLAGS) -DMAGMA_HARDEN_CANARIES
endif

ifeq "$(HOST)" "x86"
	CFLAGS := -m32 $(CFLAGS)
	CXXFLAGS := -m32 $(CXXFLAGS)
	LDFLAGS := -m32 $(LDFLAGS)
endif

.PHONY: all $(DIRS)

all: $(DIRS)
	@echo "Benchmark binaries written to $(BINDIR)"

magma:
	@cd magma; \
# 	 $(CC) $(CFLAGS) -c -o canary.h.gch canary.h $(LDFLAGS) $(LIBS); \
	 $(CC) $(CFLAGS) -D'MAGMA_STORAGE="$(MAGMA_STORAGE)"' -DMAGMA_BUG_COUNT\=$(BUG_COUNT) -c -o canary.o canary.c $(LDFLAGS) $(LIBS);
	@mkdir -p $(BINDIR)/programs
	@cd magma; \
	 $(CC) $(CFLAGS) -D'MAGMA_STORAGE="$(MAGMA_STORAGE)"' -DMAGMA_BUG_COUNT\=$(BUG_COUNT) -o monitor monitor.c $(LDFLAGS) $(LIBS) -lrt;
	@cp magma/monitor $(BINDIR)/monitor$(MAGMA_SUFFIX)

libpng16: magma
	@cd libpng16; \
	 ./configure --enable-maintainer-mode; \
	 ./autogen.sh --maintainer --clean; \
	 ./autogen.sh --maintainer; \
	 export CFLAGS="$(MAGMA_CFLAGS) $(CFLAGS)"; \
	 export CXXFLAGS="$(MAGMA_CXXFLAGS) $(CXXFLAGS)"; \
	 export LDFLAGS="$(MAGMA_LDFLAGS) $(LDFLAGS)"; \
	 export LIBS="$(MAGMA_LIBS) $(LIBS)"; \
	 export PNG_COPTS="$(MAGMA_LOG)"; \
	 { ./configure --host=$(HOST) && $(MAKE) clean all; } ;
	@cp libpng16/readpng $(BINDIR)/programs/readpng$(MAGMA_SUFFIX)

libtiff4: magma
	@cd libtiff4; \
	 ./autogen.sh; \
	 export CFLAGS="$(MAGMA_CFLAGS) $(CFLAGS)"; \
	 export CXXFLAGS="$(MAGMA_CXXFLAGS) $(CXXFLAGS)"; \
	 export LDFLAGS="$(MAGMA_LDFLAGS) $(LDFLAGS)"; \
	 export LIBS="$(MAGMA_LIBS) $(LIBS)"; \
	 export TIFF_COPTS="$(MAGMA_LOG)"; \
	 { ./configure --host=$(HOST) --disable-cxx --disable-shared && $(MAKE) clean all; } ;
	@cp libtiff4/tools/tiffcp $(BINDIR)/programs/tiffcp$(MAGMA_SUFFIX)

libxml2: magma
	@cd libxml2; \
	 export CFLAGS="$(MAGMA_CFLAGS) $(CFLAGS)"; \
	 export CXXFLAGS="$(MAGMA_CXXFLAGS) $(CXXFLAGS)"; \
	 export LDFLAGS="$(MAGMA_LDFLAGS) $(LDFLAGS)"; \
	 export LIBS="$(MAGMA_LIBS) $(LIBS)"; \
	 export XML_COPTS="$(MAGMA_LOG)"; \
	 { ./autogen.sh --host=$(HOST) --disable-shared \
	 	--with-zlib=yes \
	 	--with-lzma=yes \
	 	--with-mem-debug=yes \
	  && $(MAKE) clean all; } ;
	@cp libxml2/xmllint $(BINDIR)/programs/xmllint$(MAGMA_SUFFIX)

poppler: magma
	@cd poppler; \
	 export CFLAGS="$(CFLAGS)"; \
	 export CXXFLAGS="$(CXXFLAGS)"; \
	 export LDFLAGS="$(MAGMA_LDFLAGS) $(LDFLAGS)"; \
	 export LIBS="$(MAGMA_LIBS) $(LIBS)"; \
	 export POPPLER_COPTS="$(MAGMA_LOG) $(MAGMA_CFLAGS)"; \
	 { mkdir -p build && cd build && cmake .. \
	  	-DBUILD_GTK_TESTS:BOOL=OFF \
	  	-DBUILD_QT5_TESTS:BOOL=OFF \
	  	-DBUILD_CPP_TESTS:BOOL=OFF \
	  	-DENABLE_SPLASH:BOOL=ON \
	  	-DENABLE_CPP:BOOL=OFF \
	  	-DENABLE_GLIB:BOOL=OFF \
	  	-DENABLE_GOBJECT_INTROSPECTION:BOOL=OFF \
	  	-DENABLE_QT5:BOOL=OFF \
	  	-DENABLE_LIBCURL:BOOL=OFF \
	  	-DENABLE_ZLIB:BOOL=OFF \
	  	-DBUILD_SHARED_LIBS:BOOL=OFF \
	  	-DCMAKE_VERBOSE_MAKEFILE:BOOL=ON \
	  && $(MAKE) clean all; } ;
	@cp poppler/build/utils/pdftoppm $(BINDIR)/programs/pdftoppm$(MAGMA_SUFFIX)
	@cp poppler/build/utils/pdfimages $(BINDIR)/programs/pdfimages$(MAGMA_SUFFIX)
