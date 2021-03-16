#!/usr/bin/env python

from __future__ import print_function
import sys, errno

if __name__ == "__main__":
	print(__file__ + ": This module is not meant to be invoked directly.", file=sys.stderr)
	sys.exit(errno.ELIBEXEC)

import os
import argparse
import logging
from os import path
import traceback, signal
import code

#irods_script_dir = '/var/lib/irods/scripts'
irods_script_dir = '/home/swooshy/devstuff/renci/irods/scripts'
if 'IRODS_SCRIPTS_DIR' in os.environ:
	irods_script_dir = os.environ['IRODS_SCRIPTS_DIR']

def augment_module_search_paths():
	if not path.isabs(irods_script_dir):
		raise OSError(errno.EINVAL, "irods_script_dir is not an absoltue path", irods_script_dir)
	if not path.exists(irods_script_dir):
		raise OSError(errno.ENOENT, "irods_script_dir not found", irods_script_dir)
	if not path.isdir(irods_script_dir):
		raise OSError(errno.ENOTDIR, "irods_script_dir is not a directory", irods_script_dir)

	# If the irods script dir is already in the search paths, do nothing
	for searchpath in sys.path:
		try:
			if path.samefile(searchpath, irods_script_dir):
				return
		except OSError:
			pass

	sys.path.insert(1, irods_script_dir)

def init_logging(l, verbosity):
	from irods import log as ilog
	l.addHandler(ilog.NullHandler())
	logging.getLogger().setLevel(logging.NOTSET)

	ilog.register_tty_handler(sys.stderr, logging.ERROR, None)
	if verbosity > -2:
		ilog.register_tty_handler(sys.stderr, logging.WARNING, logging.ERROR)
	if verbosity > -1:
		ilog.register_tty_handler(sys.stdout, logging.INFO, logging.WARNING)
	if verbosity > 0:
		llevel = logging.NOTSET
		if verbosity == 1:
			llevel = logging.DEBUG
		ilog.register_tty_handler(sys.stderr, llevel, logging.INFO)

class _IncrDecrAction(argparse.Action):
	def __init__(self, option_strings, dest, nargs=None, const=None, default=None, type=None,
	             choices=None, required=False, metavar=None, **kwargs):
		if nargs is not None and nargs != 0:
			raise ValueError("nonzero nargs not allowed")
		if const is not None:
			raise ValueError("const not allowed")
		if type is not None and type != int:
			raise ValueError("non-int type not allowed")
		if choices is not None:
			raise ValueError("choices not allowed")
		if required:
			raise ValueError("non-false required not allowed")
		if metavar is not None:
			raise ValueError("metavar not allowed")

		if default is None:
			default = 0

		super(_IncrDecrAction, self).__init__(option_strings, dest, nargs=0, default=0, type=int, **kwargs)

class IncrementAction(_IncrDecrAction):
	def __call__(self, parser, namespace, values, option_string=None):
		setattr(namespace, self.dest, getattr(namespace, self.dest, self.default) + 1)

class DecrementAction(_IncrDecrAction):
	def __call__(self, parser, namespace, values, option_string=None):
		setattr(namespace, self.dest, getattr(namespace, self.dest, self.default) - 1)

def dump_stacktrace(sig, frame):
	print("Signal received", sig, file=sys.stderr)
	print("Stacktrace:", file=sys.stderr)
	print(traceback.format_stack(frame), file=sys.stderr)

def setup_stacktrace_signal():
	signal.signal(signal.SIGUSR1, dump_stacktrace)
	print("PID:", os.getpid(), file=sys.stderr)


def _generate_common_argparser():
	argparser = argparse.ArgumentParser(allow_abbrev=False, add_help=False)

	argparser.add_argument('--irods-scripts-dir', metavar='PATH',
		action='store', dest='scripts_dir',
		type=str, default=None,
		help='iRODS scripts directory')

	verbosityargs = argparser.add_argument_group('Output verbosity')

	verbosityargs.add_argument('-q', '--quiet',
		action=DecrementAction, dest='verbosity',
		type=int, default=0,
		help='Decrease verbosity')
	verbosityargs.add_argument('-v', '--verbose',
		action=IncrementAction, dest='verbosity',
		type=int, default=0,
		help='Increase verbosity')

	return argparser

common_argparser = _generate_common_argparser()
