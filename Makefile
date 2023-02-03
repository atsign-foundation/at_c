.PHONY: all build configure

all: default
build: default

default: configure
	mkdir -p lib/default
	make -C build/default all
	cp build/default/lib*.a lib/default/

configure:
	cmake -S . -B build/default

.PHONY: clean clean-default clean-esp32

clean: clean-default clean-esp32

clean-default:
	rm -rf build/default lib/default

clean-esp32:
	rm -rf build/esp32 lib/esp32

.PHONY: esp32 esp32-env esp32-tools

esp32:
	mkdir -p lib/esp32
	cp -r archetypes/esp32/main .
	idf.py -B build/esp32 -G 'Unix Makefiles' build -D BUILD_ESP_IDF=ON
	rm -rf main

esp32-env:
	. deps/esp-idf/export.sh

esp32-tools:
	deps/esp-idf/install.sh



