# desktop_mbedtls example

## How to run this example

### 1.
Open a terminal in the root of the repo.

### 2.
Run the following command to setup the environment:
```sh
./tool.py -p desktop -f mbedtls init
```

> `-p` selects the platform  
> `-f` selects the framework  
> `init` is the command being executed

### 3.
Run the following command to build the at_client library for the example app:
```sh
./tool.py -p desktop -f mbedtls build -o example/desktop_mbedtls/lib
```
> `build` is the command being executed  
> `-o` is a build option which allows a folder to be selected for output (i.e. this example app)

### 4.
Change directories to the example app:
```sh
cd example/desktop_mbedtls
```

### 5.
Use make to build and run the project:
```sh
make run
```

Alternative make commands and their usege:
> `make build`: build the project binary  
> `make desktop_mbedtls`: same as `make build`  
> `make run`: build (if needed) and run the binary  
> `make clean`: remove all files generated by the build
