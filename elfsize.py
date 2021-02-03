#!/usr/bin/env python3
"""
A tool for generating reports on the static memory size of ELF binaries.  See README.md for details,
or run elfsize.py --help for usage information.
"""

from subprocess import check_output, Popen, PIPE

try:
    from elftools.elf import elffile
    from elftools.elf.constants import SH_FLAGS
    from elftools import dwarf

    HaveElfTools = True
except ImportError:
    HaveElfTools = False

import argparse
import json
import os
import re
import string
import struct
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

class JSONOutput(Output):
    """ Output symbol size info to a json file. """
    def __init__(self, toolchain, fd):
        super(JSONOutput, self).__init__(toolchain, fd)

    def add_leaf(self, parent, pth, leaf):
        """Add a leaf node to the JSON symbol tree."""
        if 'legato' in leaf and leaf['legato']:
            parent['legato'] = True

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

    def get_symbol_tree(self, symbols):
        """ Get a json of symbols """
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
            if "legato" in symbol and symbol['legato']:
                leaf['legato'] = True

            self.add_leaf(root, symbol['path'], leaf)

        return root

    def output(self, symbols, build_info):
        """Generate JSON output."""
        root = self.get_symbol_tree(symbols);
        self.fd.seek(0)
        json.dump(root, self.fd, indent=4)
        self.fd.write("\n")
        self.close()

class JSOutput(JSONOutput):
    """Output to JavaScript suitable for d3.js visualisations."""
    def __init__(self, toolchain, fd, browser = False, also_csv = False):
        super(JSOutput, self).__init__(toolchain, fd)
        self.browser = browser
        self.also_csv = also_csv

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
            'RAM': self.toolchain.ram.copy(),
            'ROM': self.toolchain.rom.copy(),
            'RAM+ROM': self.toolchain.ram_and_rom.copy()
        }

        # First summarize all RAM overlays, and add the largest to the RAM size
        try:
            overlay_summary = [0] * len(self.toolchain.ram_overlays)

            for symbol in symbols.values():
                for i, overlay in enumerate(self.toolchain.ram_overlays):
                    if symbol['section'] in overlay:
                        overlay_summary[i] += symbol['size']

            largest_overlay = max(range(len(overlay_summary)), key=overlay_summary.__getitem__)

            section_types['RAM'].extend(self.toolchain.ram_overlays[largest_overlay])
        except:
            pass

        # Get json of symbols:
        symbol_tree_root = self.get_symbol_tree(symbols);

        # Calculate section summary:
        for symbol in symbols.values():
            for section_type, sections in section_types.items():
                if symbol['section'] in sections:
                    summary[section_type] += symbol['size']

        self.fd.seek(0)
        self.fd.write("// Automatically generated file; do not edit.\n")

        self.fd.write("var section_types = ")
        json.dump(section_types, self.fd, indent=4)
        self.fd.write("\n")

        self.fd.write("var summary_map = ")
        json.dump(summary, self.fd, indent=4)
        self.fd.write("\n")

        self.fd.write("var size_map = ")
        json.dump(symbol_tree_root, self.fd, indent=4)
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
    def __init__(self, base, source_root, legato_paths=[]):
        self.base = base
        self.source_root = source_root
        self.legato_paths = [path.split('/') for path in legato_paths]

    def strip_prefix(self, string, prefix):
        """Remove a common prefix from a string."""
        if string.startswith(prefix):
            return string[len(prefix):]
        return string

    def to_path(self, symbol):
        """Build a symbol path from the other symbol properties."""
        p = [symbol['section']]
        p += self.strip_prefix(os.path.abspath(symbol['file']), self.source_root).split(os.sep)[1:]
        return p

    def verify_compatible_node(self, symbol_name, key, old_value, new_value):
        if old_value != new_value:
            print('[WARN] updating symbol {} with unlike {} (old:{}, new:{})'
                  .format(symbol_name, key, old_value, new_value))

    def update_node(self, symbols, symbol, create):
        """Create or update a symbol map entry."""
        key = self.to_key(symbol)
        if key in symbols:
            for symbol_key in symbol:
                if symbol.get(symbol_key):
                    if not symbols[key].get(symbol_key):
                        # Add new information to a symbol.
                        symbols[key][symbol_key] = symbol[symbol_key]
                    else:
                        self.verify_compatible_node(symbols[key].get('name'),
                                                    symbol_key,
                                                    symbols[key][symbol_key], symbol[symbol_key])
        elif create:
            symbols[key] = symbol

    def build_info(self, binaries):
        """Supply some basic build information."""
        info = [
            {
                'name': 'Binary',
                'value': self.strip_prefix(
                    self.strip_prefix(os.path.abspath(binaries[0]), self.source_root), os.sep)
            },
            {
                'name': 'Time',
                'value': time.ctime(os.path.getmtime(binaries[0]))
            }
        ]
        return info

    def is_legato_path(self, path):
        for pattern in self.legato_paths:
            # First element of path is the section (.text, .bss, etc.), so cut it out
            if self.path_match(path[1:], pattern):
                return True
        return False

    def path_match(self, path, pattern):
        for i in range(len(pattern)):
            if pattern[i] == '...':
                # '...' matches any number of path segments.
                for j in range(i,len(path)):
                    if self.path_match(path[j:], pattern[i+1:]):
                        return True
                return False
            elif i >= len(path):
                return False
            elif pattern[i] == '*':
                # '*' matches any single path segment
                pass
            elif pattern[i] != path[i]:
                return False
        return True

class PyToolchain(Toolchain):
    """ELF binary analyzer using Python ELFTools to extract symbols and debug information."""
    def __init__(self, base, source_root, legato_paths=[]):
        if not HaveElfTools:
            raise RuntimeError("python3-elftools required for this toolchain")

        super(PyToolchain, self).__init__(base, source_root, legato_paths)

    def set_file_for_symbol(self, symbol, pth):
        """Collect the file path for a symbol."""
        symbol['file'] = self.strip_prefix(pth, self.source_root)

    def to_key(self, symbol):
        """Build a composite symbol lookup key from the other symbol properties."""
        if 'address' not in symbol:
            print('No address for symbol {}'.format(symbol))

        if 'section' not in symbol:
            print('No section for symbol {}'.format(symbol))

        return hash(symbol['address']) ^ hash(symbol['section'])

    def get_section_for_address(self, main_binary, address):
        for section in main_binary.iter_sections():
            if section['sh_addr'] <= address and address < section['sh_addr'] + section['sh_size']:
                return section.name
        return None

    def get_first_address(self, main_binary):
        for section in main_binary.iter_sections():
            if section['sh_flags'] & SH_FLAGS.SHF_ALLOC:
                return section['sh_addr']
        None

    def get_file_addrs(self, debug_info):
        file_addrs = []

        for cu in debug_info.iter_CUs():
            file_die = cu.get_top_DIE()

            try:
                file_addrs.append({'file': file_die.attributes['DW_AT_NAME'].value,
                                    'low_addr': file_die.attributes['DW_AT_low_pc'].value,
                                    'high_addr': file_die.attributes['DW_AT_high_pc'].value})
            except KeyError:
                pass

        return file_addrs

    def update_node(self, symbols, symbol, create):
        """Create or update a symbol map entry."""
        key = self.to_key(symbol)
        if key in symbols:
            # if no name associated with this symbol, it's a section and should be replaced
            if symbols[key].get('name') is None:
                symbols[key] = symbol
                return

            for symbol_key in symbol:
                if symbol.get(symbol_key):
                    if not symbols[key].get(symbol_key) or symbol_key in ('name', 'file', 'line'):
                        pass
                    else:
                        if (symbol_key == 'size' and
                            abs(symbol[symbol_key] - symbols[key][symbol_key]) >= 4) or \
                           (symbol_key != 'size' and
                            symbol[symbol_key] != symbols[key][symbol_key]):
                            print('[WARN] updating symbol {} with unlike symbol {}'
                                  .format(symbols[key], symbol))
                            break

            for symbol_key in symbol:
                if symbol.get(symbol_key):
                    if not symbols[key].get(symbol_key) or symbol_key in ('name', 'file', 'line'):
                        # Add new information to a symbol, and replace name, file, line with
                        # info from debug table, even if present
                        symbols[key][symbol_key] = symbol[symbol_key]

        elif create:
            symbols[key] = symbol

    def get_sorted_symbols(self, symbols):
        return iter(sorted(symbols.values(), key=lambda symbol: symbol['address']))

    def scan_symtab(self, symbols, main_binary):
        symtab =  main_binary.get_section_by_name(".symtab")

        cur_file = None

        # parse output and store in dict
        for symbol in symtab.iter_symbols():
            # Skip if not a symbol type we care about
            if symbol['st_info']['type'] == 'STT_FILE':
                base_file = self.strip_prefix(symbol.name, self.source_root)
                if base_file.find('legato') != -1:
                    cur_file = os.path.join(self.source_root, 'legato', '<unknown>')
                else:
                    cur_file = symbol.name
                continue

            if not (symbol['st_info']['type'] in ('STT_FUNC', 'STT_OBJECT', 'STT_SECTION') and
                    symbol['st_size'] != 0):
                continue

            # Also skip if not in an section loaded onto the device
            section = main_binary.get_section(symbol['st_shndx'])
            if section['sh_flags'] & SH_FLAGS.SHF_ALLOC == 0:
                continue

            # and skip everything in QSR_STRING
            if section.name == 'QSR_STRING':
                continue

            if symbol['st_info']['type'] == 'STT_FUNC':
                # On ARM a 1 in the LSB indicates thumb mode.  Prune it off.
                address = symbol['st_value'] & ~0x01
            else:
                address = symbol['st_value']

            if symbol['st_info']['type'] == 'STT_SECTION':
                symbol_name = None
            else:
                symbol_name = symbol.name

            parsed_symbol = { 'name':    symbol_name,
                              'address': address,
                              'section': section.name,
                              'line': 0,
                              'size': symbol['st_size'],
                              'path': None }

            if cur_file:
                self.set_file_for_symbol(parsed_symbol, cur_file)

            self.update_node(symbols, parsed_symbol, 1)

        # Add a fake symbol for QSR_STRING section which is blended by QShrink
        qst_section = main_binary.get_section_by_name('QSR_STRING')
        if qst_section:
            symbol = { 'name':    'QSR_STRING',
                       'address': qst_section['sh_addr'],
                       'section': 'QSR_STRING',
                       'file': '<NO_SOURCE>',
                       'line': 0,
                       'size': qst_section['sh_size'],
                       'path': None }
            self.update_node(symbols, symbol, 1)

    def scan_debuginfo(self, symbols, main_binary, debug_info):
        for cu in debug_info.iter_CUs():
            file_die = cu.get_top_DIE()

            for die in file_die.iter_children():
                symbol = None
                if die.tag == 'DW_TAG_subprogram':

                    if 'DW_AT_low_pc' not in die.attributes or \
                       die.attributes['DW_AT_low_pc'].value == 0:
                        continue

                    address = die.attributes['DW_AT_low_pc'].value

                    try:
                        name = die.attributes['DW_AT_name'].value.decode()
                    except KeyError:
                        name = None

                    if die.attributes['DW_AT_high_pc'].form == 'DW_FORM_addr':
                        symbol_size = (die.attributes['DW_AT_high_pc'].value -
                                       die.attributes['DW_AT_low_pc'].value)
                    elif die.attributes['DW_AT_high_pc'].form in ('DW_FORM_data1'
                                                                  'DW_FORM_data2'
                                                                  'DW_FORM_data4'
                                                                  'DW_FORM_data8'):
                        symbol_size = die.attributes['DW_AT_high_pc'].value
                    else:
                        print('[WARN] Unknown size for symbol {} in debug info'.format(name))
                        symbol_size = None
                    symbol = { 'name': name,
                               'address': address,
                               'section': self.get_section_for_address(main_binary,
                                                                       address),
                               'line': 0,
                               'size': symbol_size,
                               'path': None }
                    self.set_file_for_symbol(symbol,
                                             file_die.attributes['DW_AT_name'] \
                                                 .value.decode())

                elif die.tag == 'DW_TAG_variable':
                    if 'DW_AT_location' not in die.attributes:
                        continue

                    if not die.attributes['DW_AT_location'].value:
                        continue

                    if main_binary.little_endian:
                        address = struct.unpack('<L',
                                                bytearray(die
                                                          .attributes['DW_AT_location']
                                                          .value[1:]))[0]
                    else:
                        address = struct.unpack('>L',
                                                bytearray(die
                                                          .attributes['DW_AT_location']
                                                          .value[1:]))[0]

                    symbol = {'address': address,
                              'section': self.get_section_for_address(main_binary, address),
                              'line': 0,
                              'size': None,
                              'path': None }
                    self.set_file_for_symbol(symbol,
                                             file_die.attributes['DW_AT_name'] \
                                                 .value.decode())

                if symbol:
                    self.update_node(symbols, symbol, 1)

    def add_pad(self, symbols, address, size):
        symbol = { 'name': 'PAD',
                   'address': address,
                   'section': None,
                   'size': size,
                   'file': '<NONE>',
                   'line': 0,
                   'path': None }
        self.update_node(symbols, symbol, 1)

    def add_unknown(self, symbols, address, size, filename):
        symbol = { 'name': '<unknown>',
                   'address': address,
                   'section': self.get_section_for_address(main_binary,
                                                           address),
                   'size': size,
                   'file': filename,
                   'line': 0,
                   'path': None }
        self.update_node(symbols, symbol, 1)

    def add_gaps_for_address(self,
                             symbols, last_addr, address, size,
                             file_addr):
        gap = address - last_addr
        if gap < 0:
            print('[WARN] Symbol overlap at {:08x}: {}, {}'.format(address,
                                                                   symbols.get(last_addr),
                                                                   symbols.get(address)))
            return address + size
        elif gap > 0:
            if not file_addr or last_addr < file_addr['low_addr']:
                if file_addr and address > file_addr['low_addr']:
                    self.add_pad(symbols,
                                 last_addr, file_addr['low_addr'] - last_addr)
                    return file_addr['low_addr']
                else:
                    self.add_pad(symbols,
                                 last_addr, address - last_addr)
                    return address + size
            else:
                assert(address < file_addr['high_addr']) # Should be guaranteed by caller
                self.add_unknown(symbols,
                                 last_addr, address - last_addr,
                                 file_addr['file'])
                return address + size
        else:
            return address + size

    def remove_unneeded_sections(self, symbols):
        sorted_symbols = self.get_sorted_symbols(symbols)

        cur_section = None

        for symbol in sorted_symbols:
            if 'size' not in symbol or not symbol['size']:
                symbols.pop(self.to_key(symbol))
            elif 'name' not in symbol or not symbol['name']:
                cur_section = symbol
            elif cur_section:
                if symbol['address'] < cur_section['address'] + cur_section['size']:
                    # Section is broken down into symbols -- remove the section
                    symbols.pop(self.to_key(cur_section))
                    cur_section = None

    def resolve_unknowns(self, symbols, main_binary, debug_info):
        file_addrs = sorted(self.get_file_addrs(debug_info),
                            key=lambda file_addr: file_addr['low_addr'])

        padding = 0
        symbol_iter = self.get_sorted_symbols(symbols)
        file_iter = iter(file_addrs)
        try:
            file_addr = next(file_iter)
        except StopIteration:
            file_addr = None

        last_addr = self.get_first_address(main_binary)
        last_file_addr = last_addr
        last_symbol = None
        try:
            symbol = next(symbol_iter)
            while True:
                address = symbol['address']

                try:
                    if file_addr and address >= file_addr['high_addr']:
                        if last_addr < file_addr['high_addr']:
                            self.add_unknown(symbols,
                                             last_addr, file_addr['high_addr'] - last_addr,
                                             file_addr['file'])
                        last_addr = file_addr['high_addr']

                        last_file_addr = file_addr['high_addr']
                        file_addr = next(file_iter)

                        if last_file_addr < file_addr['low_addr'] and \
                           address >= file_addr['low_addr']:
                            self.add_pad(symbols,
                                         last_file_addr, file_addr['low_addr'] - last_file_addr)

                        continue
                except StopIteration:
                    file_addr = None

                if file_addr and file_addr['low_addr'] <= address:
                    assert(address < file_addr['high_addr']) # Should be guaranteed above
                    if not symbol['file']:
                        self.set_file_for_symbol(symbol, file_addr['file'])

                if not symbol['size']:
                    print('[ERR] missing size in symbol {}'.format(symbol))

                if last_symbol and last_symbol['section'] == symbol['section']:
                    last_addr = self.add_gaps_for_address(symbols,
                                                          last_addr, address, symbol['size'],
                                                          file_addr)
                else:
                    last_addr = address + symbol['size']

                if last_addr >= address:
                    # Address consumed, move on to next address
                    last_symbol = symbol
                    symbol = next(symbol_iter)
        except StopIteration:
            pass

    def scan(self, binaries):
        """
        Scan the provided binaries for symbol information.  The first binary in the list provides
        the symbols, and the remaining binaries are used to fill in missing information for that
        set of symbols.
        """
        main_binary = elffile.ELFFile(open(binaries[0], 'rb'))

        symbols = {}

        print("[INFO] collecting symbols...")

        self.scan_symtab(symbols, main_binary)

        if not main_binary.has_dwarf_info():
            return

        debug_info = main_binary.get_dwarf_info()

        print("[INFO] analyzing debug info...")

        self.scan_debuginfo(symbols, main_binary, debug_info)

        print("[INFO] removing unneeded sections...")

        self.remove_unneeded_sections(symbols)

        print("[INFO] resolving unknown symbols...")

        self.resolve_unknowns(symbols, main_binary, debug_info)

        return symbols

    def resolve(self, binaries, symbols):
        for symbol in symbols.values():
            if 'file' not in symbol or not symbol['file']:
                symbol['file'] = '<NO_SOURCE>'

            symbol['path'] = self.to_path(symbol)

            symbol['legato'] = self.is_legato_path(symbol['path'])

class GNUToolchain(Toolchain):
    """ELF binary analyser using GNU toolchain."""
    def __init__(self, base, source_root = None, prefix = "", legato_paths=[]):
        super(GNUToolchain, self).__init__(base, source_root, legato_paths)
        self.prefix = prefix
        self.nm = os.path.join(self.base, self.prefix + "nm")
        self.addr2line = os.path.join(self.base, self.prefix + "addr2line")

    def to_key(self, symbol):
        """Build a composite symbol lookup key from the other symbol properties."""
        return tuple([symbol['name'], symbol['section'], symbol['size']])

    def set_file_for_symbol(self, symbol, pth):
        """Collect the file path for a symbol."""
        parts = pth.split(':')
        symbol['file'] = self.strip_prefix(parts[0], self.source_root)
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

    def verify_compatible_node(self, symbol_name, key, old_value, new_value):
        if key != 'address':
            # Ignore mismatched address, as different ELF files will have different
            # addresses for each symbol
            super(GNUToolchain, self).verify_compatible_node(symbol_name, key,
                                                             old_value, new_value)

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
                scan_file.write(check_output(cmd).strip().decode() + "\n\n")

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
                addr2line.stdin.write((symbol['address'] + "\n").encode())
                addr2line.stdin.flush()
                line = addr2line.stdout.readline()
                parts = line.split(b" at ")
                if parts[0] == symbol['name']:
                    self.set_file_for_symbol(symbol, parts[1])
                else:
                    # print("[DEBUG] addr2line resolved incorrect location for {0}: {1}"
                    #     .format(symbol['name'], line.strip()))
                    symbol['file'] = "??"

            if not symbol['file'] or symbol['file'] == "??":
                self.set_file_for_symbol(symbol, "<NO SOURCE>:0")

            symbol['path'] = self.to_path(symbol)

            symbol['legato'] = self.is_legato_path(symbol['path'])

        addr2line.terminate()
        addr2line.wait()

class ALT1250MAPGNUToolchain(GNUToolchain):
    """ELF binary analyser using GNU toolchain for ALT1250 MAP Core."""
    device = "alt1250-map"
    ram = [".bss", ".sbss", ".ram_bss"]
    rom = [".rodata", ".rodatafiller", ".text"]
    ram_and_rom = [".data", ".exception_vector", ".ram_text", ".sdata"]

    def __init__(self, base, source_root = None, prefix = "mips-mti-elf-"):
        super(ALT1250MAPGNUToolchain, self).__init__(base, source_root, prefix)

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
        info = super(ALT1250MAPGNUToolchain, self).build_info(binaries)
        swi_version_path = os.path.join(os.path.dirname(binaries[0]), "swi_version")

        if os.access(swi_version_path, os.R_OK):
            with open(swi_version_path, "r") as swi_version:
                for line in swi_version:
                    if line.startswith("\toption"):
                        self.to_info(line, info)
        return info

class ALT1250MCUGNUToolchain(GNUToolchain):
    """ELF binary analyser using GNU toolchain for ALT1250 MCU Core."""
    device = "alt1250-mcu"
    ram = [".bss", ".heap", ".stack_dummy", ".bss_gpm1", ".bss_gpm2"]
    rom = [".rodata", ".rodatafiller", ".text"]
    ram_and_rom = [".data", ".uncached"]

    def __init__(self, base, source_root = None, prefix = "arm-none-eabi-"):
        super(ALT1250MCUGNUToolchain, self).__init__(base, source_root, prefix)

class MDM9xAPSSToolchain(PyToolchain):
    """
    ELF binary analyser for the output of the ARM RVCT toolchain for the MDM9x07's APSS.  Note that
    this "toolchain" doesn't actually use the ARM RVCT "fromelf" tool as it doesn't provide all of
    the necessary information.  Rather, the GNU tools are used since they can also read the ELF
    format.
    """
    ram = ["ZI_REGION"]
    rom = []
    ram_and_rom = ["APP_RAM", "MAIN_APP_1", "QSR_STRING"]
    device = ""
    le_config_path = ""
    legato_paths=['.../legato', '.../frameworkAdaptor']

    def __init__(self, base, source_root):
        super(MDM9xAPSSToolchain, self).__init__(base, source_root, self.legato_paths)

    def set_file_for_symbol(self, symbol, pth):
        """Collect the file path for a symbol."""
        if '\\' in pth:
            if pth[0] in string.ascii_uppercase and pth[1] == ':':
                pth = "/" + pth[0] + pth[2:]
            pth = pth.replace('\\', '/')

        while pth.startswith("../"):
            pth = pth[2:]

        super(MDM9xAPSSToolchain, self).set_file_for_symbol(symbol, pth)

    def format_section(self, raw_section):
        """Format the raw section name for symbol categorisation."""
        if raw_section in self.ram + self.rom + self.ram_and_rom:
            return raw_section
        return None

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
        info = super(MDM9xAPSSToolchain, self).build_info(binaries)
        manifest_path = os.path.join(os.path.dirname(binaries[0]), "../manifest.xml")
        le_config = os.path.join(os.path.dirname(binaries[0]), self.le_config_path)

        if os.access(manifest_path, os.R_OK):
            tree = ET.parse(manifest_path)
            node = tree.getroot().find("./image_tree/build_id")
            if node is not None:
                entry = {
                    'name': "Build ID",
                    'value': node.text
                }
                info.append(entry)

        if os.access(le_config, os.R_OK):
            with open(le_config, "r") as le_config:
                for line in le_config:
                    if line.startswith("#define LE_VERSION ") or \
                        line.startswith("#define LE_TARGET "):
                        self.to_info(line, info)
        return info



class MDM9x07APSSToolchain(MDM9xAPSSToolchain):
    """
    ELF binary analyser for the output of the ARM RVCT toolchain for the MDM9x05's APSS.
    """
    device = "mdm9x07-apss-tx"
    le_config_path = "../../../../legato/build/gill/framework/include/le_config.h"

    def __init__(self, base, source_root):
        super(MDM9x07APSSToolchain, self).__init__(base, source_root)

class MDM9x05APSSToolchain(MDM9xAPSSToolchain):
    """
    ELF binary analyser for the output of the ARM RVCT toolchain for the MDM9x07's APSS.
    """
    device = "mdm9x05-apss-tx"
    le_config_path = "../../../../legato/build/rc51/framework/include/le_config.h"

    def __init__(self, base, source_root):
        super(MDM9x05APSSToolchain, self).__init__(base, source_root)

class ALT1250MAPPyElfToolchain(PyToolchain):
    """ELF binary analyser using pyelf analyzer ALT1250 MAP Core."""
    device = "alt1250-map-pyelftools"
    ram = [".bss", ".sbss", ".ram_bss", ".ram_bss.common_pools"]
    rom = [".rodata", ".rodatafiller", ".text"]
    ram_and_rom = [".data", ".exception_vector", ".ram_text", ".sdata"]
    ram_overlays = [[".ram_bss.pools1", ".ram_bss.group1"],
                    [".ram_bss.pools2", ".ram_bss.group2"]]
    legato_paths=['.../legato', '.../frameworkAdaptor', 'modem/swi', 'modem/build', '.../octave']

    def __init__(self, base, source_root):
        super(ALT1250MAPPyElfToolchain, self).__init__(base, source_root, self.legato_paths)

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
        info = super(ALT1250MAPPyElfToolchain, self).build_info(binaries)
        swi_version_path = os.path.join(os.path.dirname(binaries[0]), "swi_version")

        if os.access(swi_version_path, os.R_OK):
            with open(swi_version_path, "r") as swi_version:
                for line in swi_version:
                    if line.startswith("\toption"):
                        self.to_info(line, info)
        return info

class ALT1250MCUPyElfToolchain(PyToolchain):
    """ELF binary analyser using pyelf analyzer ALT1250 MCU Core."""
    device = "alt1250-mcu-pyelftools"
    ram = [".bss", ".heap", ".stack_dummy", ".bss_gpm1", ".bss_gpm2"]
    rom = [".rodata", ".rodatafiller", ".text"]
    ram_and_rom = [".data", ".uncached"]
    legato_paths=[".../legato", ".../frameworkAdaptor", "build"]

    def __init__(self, base, source_root = None):
        super(ALT1250MCUPyElfToolchain, self).__init__(base, source_root, self.legato_paths)


# List of supported toolchains/environments.
_toolchains = [
    ALT1250MAPPyElfToolchain,
    ALT1250MCUPyElfToolchain,
    ALT1250MAPGNUToolchain,
    ALT1250MCUGNUToolchain,
    MDM9x07APSSToolchain,
    MDM9x05APSSToolchain,
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
            return toolchain(args.tools, args.source_root)

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
    if args.json:
        outputs['json'] = JSONOutput(toolchain, args.json)
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
    parser.add_argument('-r', '--source-root',  type = str, default=os.getcwd(),
                        help = 'path to the root of the source tree.  Paths will be given relative \
                        to this directory.')
    parser.add_argument('-s', '--json',         type = argparse.FileType('w'),
                        help = 'path of output json file.')

    # get and validate arguments
    args = parser.parse_args()

    try:
        toolchain = find_toolchain(args)

        if not toolchain:
            print("[ERROR] no toolchain specified")
            sys.exit(1)
    except RuntimeError as error:
        print("[ERROR] {}".format(error))
        sys.exit(1)

    outputs = get_outputs(args, toolchain)

    if not outputs:
        print("[ERROR] no outputs (-j, -c) specified")
        sys.exit(1)

    # parse input and write to output
    analyse(toolchain, args.binary, outputs.values())

    sys.exit(0)

if __name__ == '__main__':
    main()
