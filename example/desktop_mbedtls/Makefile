CXXFLAGS = -Iinclude
TARGET = desktop_mbedtls
LDFLAGS = -Llib -lat_client

.PHONY: all build clean run

all: build

build: desktop_mbedtls

run: desktop_mbedtls
	./$(TARGET)

desktop_mbedtls: src/main.o
	$(CXX) $(CXXFLAGS) -o $(TARGET) src/main.o $(LDFLAGS)

clean:
	rm -f src/main.o $(TARGET)

