#!/usr/bin/env python
"""
A tool for generating reports on the static memory size of ELF binaries.  See README.md for details,
or run elfsize.py --help for usage information.
"""

from __future__ import print_function
from subprocess import check_output, Popen, PIPE

import argparse
import json
import os
import re
import sys
import time
import webbrowser

# Linker sections that consume space in RAM.
RAM_SECTIONS = [
    ".bss",
    ".heap",
    ".sbss",
    ".stack_dummy"
]
# Linker sections that consume space in ROM.
ROM_SECTIONS = [
    ".rodata",
    ".rodatafiller",
    ".text"
]
# Linker sections that consume space in both RAM and ROM.
BOTH_SECTIONS = [
    ".data",
    ".exception_vector",
    ".ram_text",
    ".sdata",
    ".uncached"
]

class Output(object):
    """Symbol data formatter."""
    def __init__(self, device, fd):
        self.device = device
        self.fd = fd
        self.filename = os.path.abspath(self.fd.name)

    def close(self):
        """Close the underlying output file."""
        self.fd.close()
        print("[INFO] data written to", self.filename)

class JSOutput(Output):
    """Output to JavaScript suitable for d3.js visualisations."""
    def __init__(self, device, fd, browser = False, also_csv = False):
        super(JSOutput, self).__init__(device, fd)
        self.browser = browser
        self.also_csv = also_csv

    def add_leaf(self, parent, pth, leaf):
        """Add a leaf node to the JS symbol tree."""
        if not pth:
            parent['children'].append(leaf)
        else:
            for node in parent['children']:
                if node['name'] == pth[0]:
                    self.add_leaf(node, pth[1:], leaf)
                    return

            node = {
                'name': pth[0],
                'section': leaf['section'],
                'children': []
            }
            parent['children'].append(node)
            self.add_leaf(node, pth[1:], leaf)

    def output(self, symbols, build_info):
        """Generate JavaScript output for consumption by the the HTML interface."""
        summary = {
            'RAM': 0,
            'ROM': 0,
            'RAM+ROM': 0,
            'Device': self.device,
            'CSV': self.also_csv,
            'Build': build_info
        }

        root = {
            'name': self.device,
            'section': self.device,
            'children': []
        }
        for symbol in symbols.values():
            leaf = {
                'name': symbol['name'],
                'size': symbol['size'],
                'section': symbol['section']
            }
            self.add_leaf(root, symbol['path'], leaf)

            if symbol['section'] in RAM_SECTIONS:
                summary['RAM'] += symbol['size']
            elif symbol['section'] in ROM_SECTIONS:
                summary['ROM'] += symbol['size']
            elif symbol['section'] in BOTH_SECTIONS:
                summary['RAM+ROM'] += symbol['size']

        self.fd.seek(0)

        self.fd.write("var summary_map = ")
        json.dump(summary, self.fd, indent=4)
        self.fd.write("\n")

        self.fd.write("var size_map = ")
        json.dump(root, self.fd, indent=4)
        self.fd.write("\n")

        self.close()

        if self.browser:
            html_dir = os.path.dirname(self.filename)
            uri = "file://" + os.path.join(html_dir, "index.html")
            print("[INFO] opening in browser", uri)
            webbrowser.open(uri, new = 2)

class CSVOutput(Output):
    """Output to CSV for spreadsheet import."""
    def __init__(self, device, fd):
        super(CSVOutput, self).__init__(device, fd)

    def writeline(self, name, address, size, section, file, line, **kwargs):
        """Write one symbol's information as a CSV line."""
        self.fd.write("{0},{1},{2},{3},{4},{5}\n".format(name, address, size, section, file, line))

    def output(self, symbols, build_info):
        """Write the symbols out as lines in CSV format."""
        self.writeline("Name", "Address", "Size (B)", "Section", "File", "Line")
        for symbol in symbols.values():
            self.writeline(**symbol)
        self.close()

class Toolchain(object):
    """Binary analyser."""
    def __init__(self, base):
        self.base = base

    def strip_prefix(self, string, prefix):
        """Remove a common prefix from a string."""
        if string.startswith(prefix):
            return string[len(prefix):]
        return string

    def to_key(self, symbol):
        """Build a composite symbol lookup key from the other symbol properties."""
        return tuple([symbol['name'], symbol['section'], symbol['size']])

    def to_path(self, symbol):
        """Build a symbol path from the other symbol properties."""
        p = [symbol['section']]
        p += self.strip_prefix(os.path.abspath(symbol['file']), os.getcwd()).split(os.sep)[1:]
        return p

    def update_node(self, symbols, symbol, create):
        """Create or update a symbol map entry."""
        key = self.to_key(symbol)
        if key in symbols:
            if symbols[key]['file'] is None:
                symbols[key]['file'] = symbol['file']
        elif create:
            symbols[key] = symbol

    def build_info(self, binaries):
        """Supply some basic build information."""
        info = [
            {
                'name': 'Binary',
                'value': self.strip_prefix(
                    self.strip_prefix(os.path.abspath(binaries[0]), os.getcwd()), os.sep)
            },
            {
                'name': 'Time',
                'value': time.ctime(os.path.getmtime(binaries[0]))
            }
        ]
        return info

class GNUToolchain(Toolchain):
    """ELF binary analyser using GNU toolchain."""
    def __init__(self, base, prefix = ""):
        super(GNUToolchain, self).__init__(base)
        self.prefix = prefix
        self.nm = os.path.join(self.base, self.prefix + "nm")
        self.addr2line = os.path.join(self.base, self.prefix + "addr2line")

    def set_file_for_symbol(self, symbol, pth):
        """Collect the file path for a symbol."""
        parts = pth.split(':')
        symbol['file'] = self.strip_prefix(parts[0], os.getcwd())
        try:
            symbol['line'] = int(parts[1]) if len(parts) > 1 else 0
        except ValueError:
            symbol['line'] = 0

    def to_symbol(self, line):
        """Convert an nm line to a symbol dictionary."""
        l = [x.strip() for x in re.split(r"\||\t", line.strip())]

        if "." not in l[6]:
            return None

        try:
            node_size = int(l[4], 16)
        except ValueError:
            return None

        symbol = {
            'name': l[0],
            'address': l[1],
            'section': "." + l[6].split('.')[1],
            'file': l[7] if len(l) > 7 else None,
            'line': 0,
            'size': node_size,
            'path': None
        }
        if symbol['file'] is not None:
            self.set_file_for_symbol(symbol, symbol['file'])

        return symbol

    def scan(self, binaries):
        """
        Scan the provided binaries for symbol information.  The first binary in the list provides
        the symbols, and the remaining binaries are used to fill in missing information for that
        set of symbols.
        """
        symbols = {}

        with open(binaries[0] + ".scan.txt", "w+") as scan_file:
            for binary in binaries:
                # run nm command on binary
                cmd = [self.nm, "-lSCf", "sysv", binary]
                print("    " + " ".join(cmd))
                scan_file.write(check_output(cmd).strip() + "\n\n")

            print("[INFO] collecting symbols...")
            scan_file.seek(0)

            # parse output and store in dict
            count = 0
            for line in scan_file:
                if "Symbols from" in line:
                    count += 1
                elif "|" in line:
                    symbol = self.to_symbol(line)
                    if symbol is not None:
                        self.update_node(symbols, symbol, count == 1)

        return symbols

    def resolve(self, binaries, symbols):
        """Resolve initial symbol information to paths."""
        cmd = [self.addr2line, "-ie", binaries[0]]
        print("    " + " ".join(cmd))
        addr2line = Popen(cmd, stdout=PIPE, stdin=PIPE)

        for symbol in symbols.values():
            if symbol['file'] is None:
                addr2line.stdin.write(symbol['address'] + "\n")
                sym_file = addr2line.stdout.readline()
                self.set_file_for_symbol(symbol, sym_file)

            if symbol['file'] == "??":
                self.set_file_for_symbol(symbol, "<NO SOURCE>:0")

            symbol['path'] = self.to_path(symbol)

        addr2line.terminate()
        addr2line.wait()

class ALT1250MAPToolchain(GNUToolchain):
    """ELF binary analyser using GNU toolchain for ALT1250 MAP Core."""
    def __init__(self, base, prefix = "mips-mti-elf-"):
        super(ALT1250MAPToolchain, self).__init__(base, prefix)

    def to_info(self, line, info):
        """Convert a swi_version line to an info key/value pair."""
        l = line.split(' ')
        if len(l) > 2:
            entry = {
                'name': l[1],
                'value': " ".join(l[2:]).strip()
            }
            info.append(entry)

    def build_info(self, binaries):
        """Try to find the swi_version file near the ELF file and use it to populate build info."""
        info = super(ALT1250MAPToolchain, self).build_info(binaries)
        swi_version_path = os.path.join(os.path.dirname(binaries[0]), "swi_version")

        if os.access(swi_version_path, os.R_OK):
            with open(swi_version_path, "r") as swi_version:
                for line in swi_version:
                    if line.startswith("\toption"):
                        self.to_info(line, info)
        return info

class ALT1250MCUToolchain(GNUToolchain):
    """ELF binary analyser using GNU toolchain for ALT1250 MCU Core."""
    def __init__(self, base, prefix = "arm-none-eabi-"):
        super(ALT1250MCUToolchain, self).__init__(base, prefix)

def analyse(toolchain, binaries, outputs):
    """
    Scan the binaries and collect symbol information before outputing it in the selected
    formats.
    """
    print("[INFO] scanning binaries...")
    symbols = toolchain.scan(binaries)
    build_info = toolchain.build_info(binaries)

    print("[INFO] resolving symbols...")
    toolchain.resolve(binaries, symbols)

    print("[INFO] writing results...")
    for o in outputs:
        o.output(symbols, build_info)

def find_toolchain(args):
    """Map device types to toolchains."""
    if args.device == "alt1250-map":
        return ALT1250MAPToolchain(args.tools)
    elif args.device == "alt1250-mcu":
        return ALT1250MCUToolchain(args.tools)
    return None

def get_outputs(args):
    """Instantiate output providers based on command line arguments."""
    outputs = {}
    if args.js:
        outputs['js'] = JSOutput(args.device, args.js, browser = args.browser,
            also_csv = bool(args.csv))
    if args.csv:
        outputs['csv'] = CSVOutput(args.device, args.csv)
    return outputs

def main():
    """Run the tool."""
    parser = argparse.ArgumentParser(
                description = 'Analyse binaries and generate static memory usage reports.')

    # specify arguments
    parser.add_argument('-d', '--device',       type = str, default = "alt1250-map",
                        help = 'target device and build environment.')
    parser.add_argument('-t', '--tools',        type = str, default = "",
                        help = 'base path at which to find toolchain executables.')
    parser.add_argument('-j', '--js',           type = argparse.FileType('w'),
                        help = 'path of output JavaScript file.')
    parser.add_argument('-c', '--csv',          type = argparse.FileType('w'),
                        help = 'path of output CSV file.')
    parser.add_argument('-b', '--browser',      action = 'store_true',
                        help = 'launch the visualisation in a browser if producing JS output.')
    parser.add_argument('-i', '--binary',       type = str, required = True, nargs = '+',
                         help = 'path to the ELF binary or binaries. The first will be used to \
                         determine symbols, while subsequent files will help to fill in hierarchy.')

    # get and validate arguments
    args = parser.parse_args()
    toolchain = find_toolchain(args)
    outputs = get_outputs(args)

    if not toolchain:
        print("[ERROR] no toolchain specified")
        sys.exit(1)

    if not outputs:
        print("[ERROR] no outputs (-j, -c) specified")
        sys.exit(1)

    # parse input and write to output
    analyse(toolchain, args.binary, outputs.values())

    sys.exit(0)

if __name__ == '__main__':
    main()
