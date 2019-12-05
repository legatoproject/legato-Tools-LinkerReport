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
import string
import sys
import time
import webbrowser
import xml.etree.ElementTree as ET

class Output(object):
    """Symbol data formatter."""
    def __init__(self, toolchain, fd):
        self.toolchain = toolchain
        self.fd = fd
        self.filename = os.path.abspath(self.fd.name)

    def close(self):
        """Close the underlying output file."""
        self.fd.close()
        print("[INFO] data written to", self.filename)

class JSOutput(Output):
    """Output to JavaScript suitable for d3.js visualisations."""
    def __init__(self, toolchain, fd, browser = False, also_csv = False):
        super(JSOutput, self).__init__(toolchain, fd)
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
            'Device': self.toolchain.device,
            'CSV': self.also_csv,
            'Build': build_info
        }
        section_types = {
            'RAM': self.toolchain.ram,
            'ROM': self.toolchain.rom,
            'RAM+ROM': self.toolchain.ram_and_rom
        }

        root = {
            'name': self.toolchain.device,
            'section': self.toolchain.device,
            'children': []
        }
        for symbol in symbols.values():
            leaf = {
                'name': symbol['name'],
                'size': symbol['size'],
                'section': symbol['section']
            }
            self.add_leaf(root, symbol['path'], leaf)

            if symbol['section'] in self.toolchain.ram:
                summary['RAM'] += symbol['size']
            elif symbol['section'] in self.toolchain.rom:
                summary['ROM'] += symbol['size']
            elif symbol['section'] in self.toolchain.ram_and_rom:
                summary['RAM+ROM'] += symbol['size']

        self.fd.seek(0)
        self.fd.write("// Automatically generated file; do not edit.\n")

        self.fd.write("var section_types = ")
        json.dump(section_types, self.fd, indent=4)
        self.fd.write("\n")

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
    def __init__(self, toolchain, fd):
        super(CSVOutput, self).__init__(toolchain, fd)

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

    def format_section(self, raw_section):
        """Format the raw section name for symbol categorisation."""
        if "." in raw_section:
            return "." + raw_section.split('.')[1]
        return None

    def to_symbol(self, line):
        """Convert an nm line to a symbol dictionary."""
        l = [x.strip() for x in re.split(r"\||\t", line.strip())]

        section = self.format_section(l[6])
        if section is None:
            return None

        try:
            node_size = int(l[4], 16)
        except ValueError:
            return None

        symbol = {
            'name': l[0],
            'address': l[1],
            'section': section,
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
        cmd = [self.addr2line, "-fpie", binaries[0]]
        print("    " + " ".join(cmd))
        addr2line = Popen(cmd, stdout=PIPE, stdin=PIPE)

        for symbol in symbols.values():
            if symbol['file'] is None:
                addr2line.stdin.write(symbol['address'] + "\n")
                line = addr2line.stdout.readline()
                parts = line.split(" at ")
                if parts[0] == symbol['name']:
                    self.set_file_for_symbol(symbol, parts[1])
                else:
                    # print("[DEBUG] addr2line resolved incorrect location for {0}: {1}"
                    #     .format(symbol['name'], line.strip()))
                    symbol['file'] = "??"

            if not symbol['file'] or symbol['file'] == "??":
                self.set_file_for_symbol(symbol, "<NO SOURCE>:0")

            symbol['path'] = self.to_path(symbol)

        addr2line.terminate()
        addr2line.wait()

class ALT1250MAPToolchain(GNUToolchain):
    """ELF binary analyser using GNU toolchain for ALT1250 MAP Core."""
    device = "alt1250-map"
    ram = [".bss", ".sbss"]
    rom = [".rodata", ".rodatafiller", ".text"]
    ram_and_rom = [".data", ".exception_vector", ".ram_text", ".sdata"]

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
    device = "alt1250-mcu"
    ram = [".bss", ".heap", ".stack_dummy"]
    rom = [".rodata", ".rodatafiller", ".text"]
    ram_and_rom = [".data", ".uncached"]

    def __init__(self, base, prefix = "arm-none-eabi-"):
        super(ALT1250MCUToolchain, self).__init__(base, prefix)

class MDM9x07APSSToolchain(GNUToolchain):
    """
    ELF binary analyser for the output of the ARM RVCT toolchain for the MDM9x07's APSS.  Note that
    this "toolchain" doesn't actually use the ARM RVCT "fromelf" tool as it doesn't provide all of
    the necessary information.  Rather, the GNU tools are used since they can also read the ELF
    format.
    """
    device = "mdm9x07-apss-tx"
    ram = ["ZI_REGION"]
    rom = []
    ram_and_rom = ["APP_RAM", "MAIN_APP_1"]

    def __init__(self, base, prefix = "arm-none-eabi-"):
        super(MDM9x07APSSToolchain, self).__init__(base, prefix)

    def set_file_for_symbol(self, symbol, pth):
        """Collect the file path for a symbol."""
        if '\\' in pth:
            if pth[0] in string.ascii_uppercase and pth[1] == ':':
                pth = "/" + pth[0] + pth[2:]
            pth = pth.replace('\\', '/')

        while pth.startswith("../"):
            pth = pth[2:]

        super(MDM9x07APSSToolchain, self).set_file_for_symbol(symbol, pth)

    def format_section(self, raw_section):
        """Format the raw section name for symbol categorisation."""
        if raw_section in self.ram + self.rom + self.ram_and_rom:
            return raw_section
        return None

    def resolve(self, binaries, symbols):
        """Resolve initial symbol information to paths using the linker's map file."""
        map_path = os.path.join(os.path.dirname(binaries[0]),
            "../bsp/apps_proc_img/build/ACDNAAAZ/APPS_PROC_ACDNAAAZA.map")

        object_map = {}
        if os.access(map_path, os.R_OK):
            expr = re.compile(
                    r'^\s{4}(.*)\s+0x([0-9a-f]{8})\s+(?:Thumb Code|Data)\s+(\d+)\s+(.*\.o)\(.*$')
            with open(map_path, "r") as map_file:
                for line in map_file:
                    m = expr.match(line)
                    if m:
                        object_map[m.group(2)] = {
                            'address': m.group(2),
                            'symbol': m.group(1).strip(),
                            'size': int(m.group(3)),
                            'object': m.group(4).strip()
                        }

        for symbol in symbols.values():
            if symbol['file'] is None:
                obj_info = object_map.get(symbol['address'])
                if obj_info is not None and obj_info['size'] == symbol['size'] and \
                    obj_info['symbol'] == symbol['name']:

                    self.set_file_for_symbol(symbol, obj_info['object'])
                else:
                    self.set_file_for_symbol(symbol, "<NO SOURCE>:0")

            symbol['path'] = self.to_path(symbol)

    def to_info(self, line, info):
        """Convert an le_config line to an info key/value pair."""
        l = line.split(' ')
        if len(l) > 2:
            entry = {
                'name': l[1],
                'value': " ".join(l[2:]).strip().strip('"')
            }
            info.append(entry)

    def build_info(self, binaries):
        """Pull Legato version and APSS build ID from various places."""
        info = super(MDM9x07APSSToolchain, self).build_info(binaries)
        manifest_path = os.path.join(os.path.dirname(binaries[0]), "../manifest.xml")
        le_config_path = os.path.join(os.path.dirname(binaries[0]),
            "../../../../legato/build/gill/framework/include/le_config.h")

        if os.access(manifest_path, os.R_OK):
            tree = ET.parse(manifest_path)
            node = tree.getroot().find("./image_tree/build_id")
            if node is not None:
                entry = {
                    'name': "Build ID",
                    'value': node.text
                }
                info.append(entry)

        if os.access(le_config_path, os.R_OK):
            with open(le_config_path, "r") as le_config:
                for line in le_config:
                    if line.startswith("#define LE_VERSION ") or \
                        line.startswith("#define LE_TARGET "):
                        self.to_info(line, info)
        return info

class MDM9x05APSSToolchain(GNUToolchain):
    """
    ELF binary analyser for the output of the ARM RVCT toolchain for the MDM9x05's APSS.
    """
    device = "mdm9x05-apss-tx"

    def __init__(self, base, prefix = "arm-none-eabi-"):
        super(MDM9x05APSSToolchain, self).__init__(base, prefix)

# List of supported toolchains/environments.
_toolchains = [
    ALT1250MAPToolchain,
    ALT1250MCUToolchain,
    MDM9x07APSSToolchain,
    MDM9x05APSSToolchain
]

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
    for toolchain in _toolchains:
        if args.device == toolchain.device:
            return toolchain(args.tools)
    return None

def list_devices():
    """List the supported environments."""
    return ", ".join([t.device for t in _toolchains])

def get_outputs(args, toolchain):
    """Instantiate output providers based on command line arguments."""
    outputs = {}
    if args.js:
        outputs['js'] = JSOutput(toolchain, args.js, browser = args.browser,
            also_csv = bool(args.csv))
    if args.csv:
        outputs['csv'] = CSVOutput(toolchain, args.csv)
    return outputs

def main():
    """Run the tool."""
    parser = argparse.ArgumentParser(
                description = 'Analyse binaries and generate static memory usage reports.')

    # specify arguments
    parser.add_argument('-d', '--device',       type = str, default = "alt1250-map",
                        help = 'target device and build environment.  \
                        Supported devices: {0}.'.format(list_devices()))
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
    outputs = get_outputs(args, toolchain)

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
