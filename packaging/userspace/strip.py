#!/usr/bin/env python3

from pprint import pprint
import inspect

import shutil, sys, os, stat
import logging
import re
import errno
from os import path
import argparse

lief_imported = False
try:
	import lief
	lief_imported = True
except ImportError:
	pass

import script_common


re_unneeded_lib = re.compile("^\t(.+)$", re.MULTILINE)

def strip(lib_path, env=None, preserve_libs=False, strip_path=None, ldd_path=None, output_path=None):
	try:
		from irods import execute as ilib
	except ImportError:
		from irods import lib as ilib
	l = logging.getLogger(__name__)
	lib_fname = path.basename(lib_path)

	if output_path is not None and path.isdir(output_path):
		output_path = path.join(output_path, path.basename(libpath))
		# if output_path is still a directory, panic
		if path.isdir(output_path):
			raise OSError(errno.EISDIR, "destination path is a directory.", output_path)

	_env = os.environ.copy()
	if env is not None:
		for k, v in env.items():
			_env[k] = v
	env = _env

	if strip_path is None:
		strip_path = shutil.which('strip', path=env['PATH'])
		if strip_path is None:
			raise OSError(errno.ENOENT, "Could not find strip tool")

	strip_args = [strip_path, '--strip-unneeded', lib_path]

	if output_path is not None:
		strip_args.append('-o')
		strip_args.append(output_path)
		stripped_lib_path = output_path
	else:
		stripped_lib_path = lib_path

	ilib.execute_command(strip_args, env=env)

	if lief_imported and not preserve_libs:
		if ldd_path is None:
			ldd_path = shutil.which('ldd', path=env['PATH'])
			if ldd_path is None:
				raise OSError(errno.ENOENT, "Could not find ldd tool")

		ldd_args = [ldd_path, '-r', '-u', stripped_lib_path]

		ldd_out, ldd_err, ldd_retcode = ilib.execute_command_permissive(ldd_args, env=env)
		# ldd returns 1 if unneeded libraries are found
		if ldd_retcode == 1:
			ldd_retcode = 0
		ilib.check_command_return(ldd_args, ldd_out, ldd_err, ldd_retcode, env=env)

		unneeded_libs = [path.basename(ulibpath) for ulibpath in re_unneeded_lib.findall(ldd_out)]
		if len(unneeded_libs) < 1:
			return

		lib = lief.parse(stripped_lib_path)

		versioned_libs = [symver.name for symver in lib.symbols_version_requirement]

		for unneeded_lib in unneeded_libs:
			if lib.has_library(unneeded_lib):
				if unneeded_lib in versioned_libs:
					# TODO: figure out how to clean these out
					l.info(stripped_lib_path + ': DT_VERNEED entry found for ' +
					       unneeded_lib + ', skipping removal of DT_NEEDED entry.')
				else:
					l.debug(stripped_lib_path + ': removing DT_NEEDED entry for ' +
					        unneeded_lib + '.')
					lib.remove_library(unneeded_lib)
			else:
				l.warning(stripped_lib_path + ': ldd reports ' + unneeded_lib +
				          ' as unneeded import, but ' + unneeded_lib +
				          ' not found in imports.')

		l.debug("writing cleaned and stripped elf to " + stripped_lib_path)
		lib.write(stripped_lib_path)
	elif not preserve_libs:
		l.warning(stripped_lib_path + ': lief not imported, skipping removal of unneeded libraries.')

	os.chmod(stripped_lib_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR |
	                            stat.S_IRGRP |                stat.S_IXGRP |
	                            stat.S_IROTH |                stat.S_IXOTH)

	return 0

def _generate_common_argparser():
	argparser = argparse.ArgumentParser(allow_abbrev=False, add_help=False)

	argparser.add_argument('--preserve-unneeded-librefs',
		action='store_true', dest='preserve_libs',
		default=False,
		help='Do not remove DT_NEEDED entries for unneeded libraries')

	toolargs = argparser.add_argument_group('Tool paths')

	toolargs.add_argument('--strip-path', metavar='TOOLPATH',
		action='store', dest='strip_path',
		type=str, default=None,
		help='Path to strip tool to use')
	toolargs.add_argument('--ldd-path', metavar='TOOLPATH',
		action='store', dest='ldd_path',
		type=str, default=None,
		help='Path to ldd tool to use')

	return argparser

common_argparser = _generate_common_argparser()

def _main():
	l = logging.getLogger(__name__)
	argparser = argparse.ArgumentParser(
		description="Strip unneeded symbols and library imports",
		parents=[common_argparser, script_common.common_argparser],
		allow_abbrev=False)

	argparser.add_argument('-o', '--output', metavar='PATH',
		action='store', dest='output_path',
		type=str, default=None,
		help='Place stripped output into PATH')
	argparser.add_argument('libraries', metavar='FILE',
		action='store',
		type=str, nargs='+', default=None,
		help='ELF binaries to strip')

	options = argparser.parse_args()

	script_common.init_logging(l, options.verbosity)

	output_path_is_dir = options.output_path is not None and path.isdir(options.output_path)
	
	if len(options.libraries) > 1 and options.output_path is not None and not output_path_is_dir:
		l.error("Multiple libraries passed in, but output path " + options.output_path +
		        " is not a directory.")
		return errno.ENOTDIR

	for libpath in options.libraries:
		# We don't want to re-evaluate whether output_path is a dir every time, in case it
		# is deleted midway through. We evaluate once, and pre-evaluate full destinations
		# to avoid this potential race condition
		output_path = options.output_path
		if output_path_is_dir:
			output_path = path.join(output_path, path.basename(libpath))
			# if output_path is still a directory, panic
			if path.isdir(output_path):
				l.error("destination path " + output_path + " is a directory.")
				return errno.EISDIR

		status = strip(libpath, strip_path=options.strip_path, preserve_libs=options.preserve_libs,
			ldd_path=options.ldd_path, output_path=options.output_path)
		if status != 0:
			return status

	return 0

if __name__ == "__main__":
	script_common.augment_module_search_paths()
	sys.exit(_main())
