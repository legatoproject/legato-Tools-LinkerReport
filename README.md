elfsize
=======
This tool is a heavily modified version of the linker report generator originally developed for
mbedOS: https://github.com/ARMmbed/mbed-os-linker-report.

This script analyses build products and generates reports about the static memory usage of the
primary executable.  In this context, the term "static memory" is used to refer to all of the ROM
occupied by program text, read-only data, etc. and all of the RAM occupied by BSS, data and so on.
Dynamic memory allocation in the form of heap usage (malloc, etc.) is **not** included in this
analysis since it cannot be determined at build time.

Usage
-----
```
usage: elfsize.py [-h] [-d DEVICE] [-t TOOLS] [-j JS] [-c CSV] [-b] -i BINARY
                  [BINARY ...]

Analyse binaries and generate static memory usage reports.

optional arguments:
  -h, --help            show this help message and exit
  -d DEVICE, --device DEVICE
                        target device and build environment.
  -t TOOLS, --tools TOOLS
                        base path at which to find toolchain executables.
  -j JS, --js JS        path of output JavaScript file.
  -c CSV, --csv CSV     path of output CSV file.
  -b, --browser         launch the visualisation in a browser if producing JS
                        output.
  -i BINARY [BINARY ...], --binary BINARY [BINARY ...]
                        path to the ELF binary or binaries. The first will be
                        used to determine symbols, while subsequent files will
                        help to fill in hierarchy.
```

Details
-------
 * `--device DEVICE`: Specify the target device/environment of the build.  The current options are
   **alt1250-map** (the default) and **alt1250-mcu**.
 * `--tools TOOLS`: Provide the base directory to search for the target-specific tools necessary for
   analysing the binaries.  For example, for a GNU toolchain, this is where `nm` and `addr2line` can
   be found.
 * `--js JS`: Provide the path of the JavaScript file to export.  To use this file with the included
   HTML page, it should replace the `html/data-flare.js` file.
 * `--csv CSV`: Provide the path of the CSV file to export.  This file contains all of the symbol
   information gathered by the script and can be used for further analysis in a spreadsheet or as
   input to another script.
 * `--browser`: Launch a web browser instance to view the generated HTML report.  Only relevent if
   the `-j` option is also provided.
 * `--binary BINARY [BINARY ...]`: Provide the path to the main executable ELF file to analyse.
   Additional ELF files, libraries, and object files that are linked into the main executable may be
   provided to help resolve symbol information, particularly source file names.

Example
-------
This command will generate a JavaScript report for the ALT1250-MAP AppFW executable:

```bash
../LinkerReport/elfsize.py -t ./toolchain/bin -j ../LinkerReport/html/data-flare.js -i map/build/AppFW_flash_no_fs.elf $(find build/ -name *.o | tr '\n' ' ') $(find legato/build/hl78 -name *.o | tr '\n' ' ')
```

Extending elfsize
-----------------
This script may be extended to add new device toolchains and output generators.

To add a new toolchain and device type, subclass Toolchain or one of its decendents, and ensure the
necessary methods are implemented:

 * `scan`
 * `build_info`
 * `resolve`

See the implementations of `GNUToolchain` and `ALT1250MAPToolchain` for examples.  To use the
toolchain, add an `elif` statement testing for the new device type and instantiating the toolchain
class in `find_toolchain()`.

To add a new output provider, subclass Output or one of its decendents, and ensure the necessary
methods are implemented:

 * `close`
 * `output`

See the implementations of `JSOutput` and `CSVOutput` for examples.  To use the output, add an
argument to the command line arguments in `main()` and an `if` statement testing for the argument
and instantiating the output class in `get_outputs()`.
