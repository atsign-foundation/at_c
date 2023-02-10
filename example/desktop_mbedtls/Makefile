# The location of the include folder:
CXXFLAGS = -I../../include

# The name of the output target:
TARGET = desktop_mbedtls

# The location of the library folder, and names of libraries to link:
LDFLAGS = -Llib -lat_client -lmbedcrypto

.PHONY: all build clean run

all: build

build: desktop_mbedtls

run: desktop_mbedtls
	./$(TARGET)

desktop_mbedtls: src/main.o
	$(CXX) $(CXXFLAGS) -o $(TARGET) src/main.o $(LDFLAGS)

clean:
	rm -f src/main.o $(TARGET)

