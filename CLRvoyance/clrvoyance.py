from argparse import ArgumentParser
import struct
import sys
import os

""" CLRvoyance
Generates shellcode for loading managed assemblies into unmanaged processes
"""

LENGTH = {
	'32' : {'SAB':0x1b5, 'MEMCPY':0x221},
	'64' : {'SAB':0x2aa, 'MEMCPY':0x346}
}

def dump_c(shellcode):
    sc_array = []
    for i in range(len(shellcode)):
        pos = i % 16
        str = ''
        if pos == 0:
            str += '"'
        str += '\\x%02x' % shellcode[i]
        if i == len(shellcode) - 1:
            str += '";\n'
        elif pos == 16 - 1:
            str += '"\n'
        sc_array.append(str)

    shellcode_str = ''.join(sc_array)
    return shellcode_str

def dump_net(shellcode):
    sc = []
    string = 'byte[] shellcode={'
    for i in range(len(shellcode)):
        if i % 16 == 0:
            str = '\n0x%02x' % shellcode[i]
        else:
            str = '0x%02x' % shellcode[i]
        sc.append(str)
    string += ','.join(sc) + '};'
    return string

def dump(options):
	assembly = open(options.assembly, 'rb').read()
	if options.dump == "c":
		print(dump_c(assembly))
	elif options.dump == "net":
		print(dump_net(assembly))
	else:
		print('[-] Unknown output type: %s' % options.dump)
		print('[-] Supported: c, net')

def run(options):
	if not os.path.exists(options.assembly):
		print('[-] %s not found' % options.assembly)
		return

	if options.dump:
		return dump(options)

	assembly = open(options.assembly, 'rb').read()
	if options.apc and not options.new_domain:
		bootstrap = open("sc-%s-clr-apc" % options.platform, 'rb').read()
	elif options.apc and options.new_domain and options.platform == "32":
		bootstrap = open("sc-%s-clrnd-apc" % options.platform, 'rb').read()
	elif options.new_domain:
		bootstrap = open("sc-%s-clrnd" % options.platform, 'rb').read()
	else:
		bootstrap = open("sc-%s-clr" % options.platform, 'rb').read()

	print('[+] %d byte assembly' % len(assembly))
	print('[+] %d byte bootstrap' % len(bootstrap))

	first_sab = bootstrap.find(b"AAAA")
	if not first_sab or first_sab == 0:
		print('[-] Length not found in bootstrap!')
		sys.exit(1)

	second_memcpy = bootstrap[first_sab+1:].find(b"AAAA")
	if not second_memcpy or second_memcpy == 0:
		print('[-] Length not found in bootstrap (memcpy)!')
		sys.exit(1)

	assembly_len = struct.pack("<I", len(assembly))

	# pack new length for SafeArrayBounds and memcpy
	_bootstrap = list(bootstrap)[:-1]
	_bootstrap[first_sab] = assembly_len[0]
	_bootstrap[first_sab+1] = assembly_len[1]
	_bootstrap[first_sab+2] = assembly_len[2]
	_bootstrap[first_sab+3] = assembly_len[3]

	_bootstrap[first_sab+1+second_memcpy] = assembly_len[0]
	_bootstrap[first_sab+1+second_memcpy+1] = assembly_len[1]
	_bootstrap[first_sab+1+second_memcpy+2] = assembly_len[2]
	_bootstrap[first_sab+1+second_memcpy+3] = assembly_len[3]

	assembled = bytes(_bootstrap) + assembly
	with open("%s.shellcode" % options.assembly, 'wb') as f:
		f.write(assembled)

	print('[+] %d byte shellcode written out (%s.shellcode)' % (len(assembled), options.assembly))

def parse():
	parser = ArgumentParser()
	parser.add_argument("-a", help="Assembly", action='store', metavar='[executable]',
						dest='assembly', required=True)
	parser.add_argument("-p", help="Platform", action='store', metavar='[32|64]',
						dest='platform', default='32')
	parser.add_argument("-d", help="Dump binary shellcode of assembly", action="store",
						metavar="[net|c]", dest='dump')
	parser.add_argument("-n", help="Load assembly into a new domain", action="store_true",
						dest='new_domain'),
	parser.add_argument("--apc", help="Use safe APC shellcode", action='store_true',
						dest='apc', default=False)
	return parser.parse_args()

if __name__ == "__main__":
	run(parse())