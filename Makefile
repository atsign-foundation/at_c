ifeq ($(OS),Windows_NT)
    detected_OS := Windows
		ext := bat
else
    detected_OS := $(shell sh -c 'uname 2>/dev/null || echo Unknown')
		ext := sh
endif

.PHONY: submodules init-esp32
install: submodules init-esp32

submodules:
	git submodule update --init --recursive

init-esp32:
	./deps/espidf/install.$(ext)

### Old Stuff to be migrated to python:
.PHONY: all build configure

all: default
build: default

default: configure
	mkdir -p lib/default
	make -C build/default all
	cp build/default/lib*.a lib/default/

configure:
	cmake -S . -B build/default

.PHONY: clean clean-default

clean: clean-default

clean-default:
	rm -rf build/default lib/default

