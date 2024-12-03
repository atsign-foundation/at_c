# atauth

Building atauth from source code will output an atactivate binary that can be used to activate an atsign.

## Building Source

Below are instructions on building the atauth package from source code using [CMake](https://cmake.org/). It is assumed that you have CMake installed. If you do not have CMake installed, you can typically download it using your package manager like `apt-get` or `brew` or even `pip`.

### Installing on Linux/MacOS

1. Get ahold of the source code either via git clone or from downloading the source from our releases:

```bash
git clone https://github.com/atsign-foundation/at_c
cd at_c/packages/atauth
```

2. CMake configure

```bash
cmake -S . -B build
```

3. Build

```bash
cmake --build build
```

4. Now you have the `atactivate` binary which can be found in the `build` directory.

```bash
cd build
./atactivate
```

You should get an output similar to the following:

```bash
jeremy@atsign:~/GitHub/at_c_docs/packages/atauth/build$ ./atactivate 
Error: -a (atsign) is mandatory.
Usage: ./atactivate -a atsign -c cram-secret -o otp [-r root-server] [-p port]
Cannot proceed without either of CRAM secret on enroll OTP.
Usage: ./atactivate -a atsign -c cram-secret -o otp [-r root-server] [-p port]
[ERROR] 2024-12-03 03:25:43.062391 | atactivate | Aborting with exit code: 1
```
