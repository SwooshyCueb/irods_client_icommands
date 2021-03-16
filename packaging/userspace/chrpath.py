#!/usr/bin/env python

from __future__ import print_function
import sys, errno

if __name__ == "__main__":
	print(__file__ + ": This module is not meant to be invoked directly.", file=sys.stderr)
	sys.exit(errno.ELIBEXEC)

import shutil, os, stat
import logging
from os import path

import script_common

lief_imported = False
try:
	import lief
	lief_imported = True
except ImportError:
	pass

def set_rpath(lib_paths, rpath='$ORIGIN/../lib', set_origin=True, env=None, chrpath_path=None, output_path=None):
	try:
		from irods import execute as ilib
	except ImportError:
		from irods import lib as ilib
	l = logging.getLogger(__name__)

	single_source = True
	try:
		path.isfile(lib_paths)
		lib_paths = [lib_paths]
	except TypeError:
		# assume lib_paths is iterable
		# make it a list if it isn't already
		if not isinstance(lib_paths, list):
			_lib_paths = []
			_lib_paths.extend(lib_paths)
			lib_paths = _lib_paths
		single_source = len(lib_paths) == 1

	if output_path is None:
		output_paths = lib_paths.copy()
	elif path.isdir(output_path):
		if single_source:
			output_path = path.join(output_path, path.basename(libpath))
			# if output_path is still a directory, panic
			if path.isdir(output_path):
				raise OSError(errno.EISDIR, "destination path is a directory.", output_path)
			output_paths = [output_path]
		else:
			output_paths = [path.combine(output_path, path.basename(l)) for l in lib_paths]
	elif not single_source:
		raise TypeError("output_path must be directory or None with multiple lib_paths")

	if chrpath_path is None:
		chrpath_path = shutil.which('chrpath', path=env['PATH'])

	if lief_imported:
		for lidx in range(0, len(lib_paths)):
			lib_path = lib_paths[lidx]
			out_path = output_paths[lidx]

			lib = lief.parse(lib_path)

			if lib.has(lief.ELF.DYNAMIC_TAGS.FLAGS):
				ent_flags = lib.get(lief.ELF.DYNAMIC_TAGS.FLAGS)
				ent_flags.add(lief.ELF.DYNAMIC_FLAGS.ORIGIN)
			else:
				ent_flags = lief.ELF.DynamicEntryFlags(lief.ELF.DYNAMIC_TAGS.FLAGS,
					int(lief.ELF.DYNAMIC_FLAGS.ORIGIN))
				lib.add(ent_flags)

			if lib.has(lief.ELF.DYNAMIC_TAGS.FLAGS_1):
				ent_flags_1 = lib.get(lief.ELF.DYNAMIC_TAGS.FLAGS_1)
				ent_flags_1.add(lief.ELF.DYNAMIC_FLAGS_1.ORIGIN)
			else:
				ent_flags_1 = lief.ELF.DynamicEntryFlags(lief.ELF.DYNAMIC_TAGS.FLAGS_1,
					int(lief.ELF.DYNAMIC_FLAGS_1.ORIGIN))
				lib.add(ent_flags_1)

			# if we have rpath but no runpath, change rpath to runpath
			if lib.has(lief.ELF.DYNAMIC_TAGS.RPATH) and not lib.has(lief.ELF.DYNAMIC_TAGS.RUNPATH):
				lib.get(lief.ELF.DYNAMIC_TAGS.RPATH).tag = lief.ELF.DYNAMIC_TAGS.RUNPATH
			# remove any other rpath entries
			while lib.has(lief.ELF.DYNAMIC_TAGS.RPATH):
				lib.remove(lief.ELF.DYNAMIC_TAGS.RPATH)

			if lib.has(lief.ELF.DYNAMIC_TAGS.RUNPATH):
				ent_runpath = lib.get(lief.ELF.DYNAMIC_TAGS.RUNPATH)
				ent_runpath.paths = [rpath]
			else:
				ent_runpath = lief.ELF.DynamicEntryRunPath(rpath)
				lib.add(ent_runpath)

			lib.write(out_path)
			os.chmod(out_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR |
			                   stat.S_IRGRP |                stat.S_IXGRP |
			                   stat.S_IROTH |                stat.S_IXOTH)
	elif chrpath_path is None:
		raise OSError(errno.ENOPKG, "lief could not be imported and chrpath could not be found")
	else:
		l.warning('lief not imported, cannot set DF_ORIGIN flag.')

		for lidx in range(0, len(lib_paths)):
			shutil.copyfile(lib_paths[lidx], output_paths[lidx])

		chrpath_args = [chrpath_path, '-c', '-r', rpath]
		chrpath_args.extend(output_paths)

		ilib.execute_command(chrpath_args, env=env)
