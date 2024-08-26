# atclient_esp32_components

This example shows you how to import `atclient`, `atlogger`, `uuid4` and `atchops` as IDF components in your project.

This is the recommended way of importing our component locally.

1. First, copy and paste the `atclient`, `atlogger`, `uuid4` and `atchops` directories into your project's `components` directory.

Your `~/esp/esp-idf/components/` directory should look like this:

```plaintext
~/esp/esp-idf/components/
├── atclient
│   ├── CMakeLists.txt
│   ├── ...
├── atlogger
│   ├── CMakeLists.txt
│   ├── ...
├── atchops
│   ├── CMakeLists.txt
│   ├── ...
└── uuid4
    ├── CMakeLists.txt
    ├── ...
```

2. In your main component, add `atclient` as a requirement in your `CMakeLists.txt` file:

`./main/CMakeLists.txt`:

```cmake
idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS ""
    REQUIRES atclient
)
```
