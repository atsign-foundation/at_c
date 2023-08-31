# repl_esp32

This example is a command line interface for interacting with the atProtocol. Works on ESP32, not tested on other devices that can run the IDF. You will be able to interact with your atServer through the command-line which will run on your ESP32.

## Running the REPL

You will need the [IDF toolchain](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/build-system.html#idf-py) to build and flash to your device.

1. Get IDF

```
get_idf
```

2. Build

```
idf.py build
```

3. Menuconfig, set your SSID and Password in "repl_esp32 WiFi Configuration"

```
idf.py menuconfig
```

4. Build, Flash and Monitor

```
idf.py build && idf.py flash monitor
```
