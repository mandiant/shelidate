# shelidate

A shellcode integration testing harness. shelidate can be used standalone to confirm payload callbacks without standing up a full command and control framework or integrated into the testing process to ensure payloads execute properly.

## Usage

```
Usage of shelidate.exe:
  -address string
        shellcode listener address (default "127.0.0.1:1337")
  -command string
        command to execute while listening, use {{.Shellcode}} to substitute the shellcode file
  -timeout string
        timeout duration (only used if commmand is specified) (default "30s")
```

### Examples

Generate shellcode that calls back to `127.0.0.1:1337` and listen indefinitely:

```
shelidate.exe
```

Generate shellcode, run the command `shellcode_runner.exe C:\Path\To\Shellcode`, and time out after 30 seconds

```
shelidate.exe -command 'shellcode_runner.exe {{.Shellcode}}'
```

## Setup

shelidate expects Go 1.22 on Windows to build. shelidate can be build with

```
go build -o shelidate ./cmd/...
```

### Building shellcode

[MinGW-w64](https://www.mingw-w64.org/) must be installed and `gcc` and `objcopy` must be available on the path to rebuild the shellcode, `shelidate.bin`.

The initial executable can be built with:

```
gcc shellcode/main.c -o shelidate.exe --entry=entry -nostdlib -ffunction-sections -fno-asynchronous-unwind-tables -fno-ident '-Wl,--strip-all,--no-seh,-Tshellcode/main.S'
```

The shellcode can be extracted with:

```
objcopy -O binary --only-section=.text shelidate.exe shelidate.bin
```
