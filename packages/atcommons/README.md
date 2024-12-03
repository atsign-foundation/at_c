# atcommons

atcommons is a package that contains common utilities and data structures used
across the atSDK.

## Building Source

You can build atcommons from source and receive a static library,
`libatcommons.a`, to be used in your projects.

1. Get ahold of the source code either via git clone or from downloading the
source from our releases:

```sh
git clone https://github.com/atsign-foundation/at_c.git
cd at_c/packages/atcommons
```

2. CMake configure

```sh
cmake -S . -B build
```

3. Build

```sh
cmake --build build
```

4. Now you have the `libatcommons.a` static library which can be found in the
`build` directory.

```sh
cd build
ls -l libatcommons.a
```
