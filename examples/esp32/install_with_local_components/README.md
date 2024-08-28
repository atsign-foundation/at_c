# install_with_components

This example is for developers who are developing on our components locally while debugging on an Espressif device.

Let's say you have cloned our components (or are developing on our SDK locally):

- [atclient](https://github.com/atsign-foundation/at_c/tree/trunk/packages/atclient)
- [atlogger](https://github.com/atsign-foundation/at_c/tree/trunk/packages/atlogger)
- [atchops](https://github.com/atsign-foundation/at_c/tree/trunk/packages/atchops)
- [uuid4](https://github.com/atsign-foundation/uuid4)

This example shows you how to import `atclient`, `atlogger`, `uuid4` and `atchops` as IDF components in your project.

This is the recommended way of importing our component locally.

1. Head over to `atclient/idf_component.yml` and comment out the `dependencies` section:

It should look like this:

```yml
version: "0.1.0"
description: "core atclient implementation of the atProtocol"
url: "https://github.com/atsign-foundation/at_c"
license: "BSD-3-Clause"
# dependencies:
#   atsign-foundation/atchops:
#     version: "0.1.0"
#   atsign-foundation/atlogger:
#     version: "0.1.0"
```

2. Do the same for `atchops/idf_component.yml`:

```yml
version: "0.1.0"
description: "cryptographich operations tailored for atProtocol"
url: "https://github.com/atsign-foundation/at_c"
license: "BSD-3-Clause"
# dependencies:
#   atsign-foundation/atlogger:
#     version: "0.1.0"
#   atsign-foundation/uuid4:
#     version: "1.0.3"
```

3. Use the EXTRA_COMPONENT_DIRS variable in your project's `./CMakeLists.txt` file.

To use the `EXTRA_COMPONENT_DIRS` variable in your project's `./CMakeLists.txt` file, you can modify the content as follows:

```cmake
set(EXTRA_COMPONENT_DIRS /path/to/atclient /path/to/atlogger /path/to/atchops /path/to/uuid4)
```

Make sure to replace `/path/to` with the actual paths to the respective directories in your project.

4. In your main component, add `atclient` as a requirement in your `CMakeLists.txt` file:

`./main/CMakeLists.txt`:

```cmake
idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS ""
    REQUIRES atclient
)
```
