#!/usr/bin/env python3

from pprint import pprint
import inspect

import shutil, sys, os, stat
import logging
import re
import errno
from os import path
import argparse
import mimetypes

import script_common, strip, chrpath

def create_tarball(options, source_dir, env=None):
	try:
		from irods import execute as ilib
	except ImportError:
		from irods import lib as ilib

	_env = os.environ.copy()
	if env is not None:
		for k, v in env.items():
			_env[k] = v
	env = _env
	env['LANG'] = 'C'

	tar_path = options.tar_path
	if tar_path is None:
		# prefer bsdtar
		tar_path = shutil.which('bsdtar', path=env['PATH'])
		if tar_path is None:
			tar_path = shutil.which('tar', path=env['PATH'])
			if tar_path is None:
				raise OSError(errno.ENOENT, "Could not find tar tool")

	tar_ver_out, tar_ver_err = ilib.execute_command([tar_path, '--version'], env=env)
	tar_ver_out = tar_ver_out.parition('\n')[0]

	is_bsdtar = 'bsdtar' in tar_ver_out
	is_gnutar = 'GNU tar' in tar_ver_out

	if not is_bsdtar and not is_gnutar:
		raise OSError(errno.ENOPKG, "tar tool incompatible (only GNU tar and bsdtar are supported)")

	tar_args = [tar_path, '-c', '-a', '-f', options.output_path]

	if is_bsdtar:
		tar_args.append('--no-fflags')
		# bsdtar will derive format from filename
		tar_args.extend(['--numeric-owner', '--uid', '0', '--gid', '0'])
	elif bsdtar:
		# GNU tar has no equivalent for --no-fflags
		tar_args.extend(['-H', 'posix'])
		tar_args.extend(['--numeric-owner', '--owner=0', '--group=0'])

	tar_args.extend(['-C', source_dir])
	tar_args.extend(os.listdir(source_dir))

	ilib.execute_command(tar_args, env=env)

def prepare_icommands(options, dest_prefix, use_destdir=False, env=None):
	try:
		from irods import execute as ilib
	except ImportError:
		from irods import lib as ilib

	_env = os.environ.copy()
	if env is not None:
		for k, v in env.items():
			_env[k] = v
	env = _env

	cmake_path = options.cmake_path
	if cmake_path is None:
		cmake_path = shutil.which('cmake', path=env['PATH'])
		if tar_path is None:
			raise OSError(errno.ENOENT, "Could not find cmake tool")


	cmake_args_base = [cmake_path, '--install', options.build_dir]

	cmake_pfx = path.join(options.work_dir, 'cmake_pfx')

	if path.exists(cmake_pfx):
		shutil.rmtree(cmake_pfx)
	os.mkdir(cmake_pfx)

	if not use_destdir:
		cmake_args_base.extend(['--prefix', cmake_pfx])

	if options.install_targets:
		cmake_args = cmake_args_base.copy()
		cmake_args.extend(options.install_targets)
		if use_destdir:
			cmake.args.append('DESTDIR=' + cmake_pfx)

		ilib.execute_command(cmake_args, env=env)

	for install_component in options.install_components:
		cmake_args = cmake_args_base.copy()
		cmake_args.extend(['--component', install_component])
		if use_destdir:
			cmake.args.append('DESTDIR=' + cmake_pfx)

		ilib.execute_command(cmake_args, env=env)

	# for now, assume everything we want is in $/bin
	dest_bin = path.join(dest_prefix, "bin")
	if not path.exists(dest_bin):
		os.mkdir(dest_bin)

	if path.isabs(options.install_bindir):
		cmake_pfx_bin = path.join(cmake_pfx, options.install_bindir[1:])
	elif path.isabs(options.cmake_install_prefix):
		cmake_pfx_bin = path.join(cmake_pfx, options.cmake_install_prefix[1:], options.install_bindir)
	else:
		cmake_pfx_bin = path.join(cmake_pfx, options.cmake_install_prefix, options.install_bindir)

	icommand_names = list(os.listdir(cmake_pfx_bin))
	icommand_binaries = set(icommand_names)

	for icommand_script in options.script_icommands:
		if icommand_script in icommand_binaries:
			icommand_path_in = path.join(cmake_pfx_bin, icommand_script)
			icommand_path_out = path.join(dest_bin, icommand_script)

			icommand_binaries.remove(icommand_script)

			shutil.copyfile(icommand_path_in, icommand_path_out)
			os.chmod(icommand_path_out, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR |
			                            stat.S_IRGRP |                stat.S_IXGRP |
			                            stat.S_IROTH |                stat.S_IXOTH)

	binaries_ret = set()

	for icommand_binary in icommand_binaries:
		icommand_path_in = path.join(cmake_pfx_bin, icommand_binary)
		icommand_path_out = path.join(dest_bin, icommand_binary)
		strip.strip(icommand_path_in, env=env, strip_path=options.strip_path,
			ldd_path=options.ldd_path, output_path=icommand_path_out)

		binaries_ret.add(icommand_path_out)

	return binaries_ret

def prepare_irods_runtime(options, dest_prefix, env=None):
	dest_lib = path.join(dest_prefix, "lib")
	if not path.exists(dest_lib):
		os.mkdir(dest_lib)

	# for now, assume irods package prefix will always be specified
	if path.isabs(options.irods_plugsdir):
		src_plugins = options.irods_plugsdir
	else:
		src_plugins = path.join(options.irods_package_prefix, options.irods_plugsdir)
	# for now, assume irods was built to look in $libdir/irods/plugins for plugins
	dest_lib_irods = path.join(dest_lib, "irods")
	if not path.exists(dest_lib_irods):
		os.mkdir(dest_lib_irods)
	dest_plugins = path.join(dest_lib_irods, "plugins")
	if not path.exists(dest_plugins):
		os.mkdir(dest_plugins)

	# for now, assume all we need are auth and network plugins
	# and assume all plugins in these directories are part of the runtime pkg
	src_plugins_auth = path.join(src_plugins, "auth")
	dest_plugins_auth = path.join(dest_plugins, "auth")
	if not path.exists(dest_plugins_auth):
		os.mkdir(dest_plugins_auth)
	src_plugins_ntwk = path.join(src_plugins, "network")
	dest_plugins_ntwk = path.join(dest_plugins, "network")
	if not path.exists(dest_plugins_ntwk):
		os.mkdir(dest_plugins_ntwk)
	
	# we know we're dealing with an actual file tree at this point
	# so let's have an in:out dict
	runtime_libs = dict()
	
	# for now, assume everything passed through --irods-externals-lib is in $/lib
	for lib_in in options.irods_runtime_libs:
		runtime_libs[lib_in] = path.join(dest_lib_irods, path.basename(lib_in))

	for plugfname in os.listdir(src_plugins_auth):
		runtime_libs[path.join(src_plugins_auth, plugfname)] = path.join(dest_plugins_auth, plugfname)

	for plugfname in os.listdir(src_plugins_ntwk):
		runtime_libs[path.join(src_plugins_ntwk, plugfname)] = path.join(dest_plugins_ntwk, plugfname)

	for lib_in, lib_out in runtime_libs.items():
		strip.strip(lib_in, env=env, strip_path=options.strip_path,
			ldd_path=options.ldd_path, output_path=lib_out)

	return set(runtime_libs.values())


def _main():
	l = logging.getLogger(__name__)


	argparser = argparse.ArgumentParser(
		description="Package icommands userspace tarball",
		parents=[strip.common_argparser, script_common.common_argparser],
		allow_abbrev=False)
	for argsgroup in argparser._action_groups:
		if argsgroup.title == 'Tool paths':
			toolargs = argsgroup

	argparser.add_argument('-o', '--output', metavar='FILE',
		action='store', dest='output_path',
		type=str, default=None,
		help='Create tarball at PATH')

	argparser.add_argument('--target-platform', metavar='PLATFORM',
		action='store', dest='target_platform',
		type=str, default=None)
	argparser.add_argument('--target-platform-variant', metavar='VARIANT',
		action='store', dest='target_platform_variant',
		type=str, default=None)

	argparser.add_argument('--cmake-install-prefix', metavar='PATH',
		action='store', dest='cmake_install_prefix',
		type=str, default='/usr')
	argparser.add_argument('--cmake-install-bindir', metavar='PATH',
		action='store', dest='install_bindir',
		type=str, default='bin')
	argparser.add_argument('--cmake-install-sbindir', metavar='PATH',
		action='store', dest='install_sbindir',
		type=str, default='sbin')
	argparser.add_argument('--cmake-install-libdir', metavar='PATH',
		action='store', dest='install_libdir',
		type=str, default='lib')

	argparser.add_argument('--irods-install-prefix', metavar='PATH',
		action='store', dest='irods_install_prefix',
		type=str, default='/usr')
	argparser.add_argument('--irods-package-prefix', metavar='PATH',
		action='store', dest='irods_package_prefix',
		type=str, default='/usr')
	argparser.add_argument('--irods-install-bindir', metavar='PATH',
		action='store', dest='irods_bindir',
		type=str, default='bin')
	argparser.add_argument('--irods-install-sbindir', metavar='PATH',
		action='store', dest='irods_sbindir',
		type=str, default='sbin')
	argparser.add_argument('--irods-install-libdir', metavar='PATH',
		action='store', dest='irods_libdir',
		type=str, default='lib')
	argparser.add_argument('--irods-pluginsdir', metavar='PATH',
		action='store', dest='irods_plugsdir',
		type=str, default='lib/irods/plugins')

	argparser.add_argument('--irods-runtime-lib', metavar='FILE',
		action='append', dest='irods_runtime_libs',
		type=str, default=[])
	argparser.add_argument('--irods-externals-lib', metavar='FILE',
		action='append', dest='irods_externals_libs',
		type=str, default=[])

	toolargs.add_argument('--tar-path', metavar='TOOLPATH',
		action='store', dest='tar_path',
		type=str, default=None,
		help='Path to tar tool to use')
	toolargs.add_argument('--chrpath-path', metavar='TOOLPATH',
		action='store', dest='chrpath_path',
		type=str, default=None,
		help='Path to chrpath tool to use if lief cannot be imported')
	toolargs.add_argument('--cmake-path', metavar='TOOLPATH',
		action='store', dest='cmake_path',
		type=str, default=None,
		help='Path to cmake tool to use')

	toolargs.add_argument('--script-icommand', metavar='NAME',
		action='append', dest='script_icommands',
		type=str, default=[])

	argparser.add_argument('--build-dir', metavar='PATH',
		action='store', dest='build_dir',
		type=str, default=os.getcwd())

	argparser.add_argument('--work-dir', metavar='PATH',
		action='store', dest='work_dir',
		type=str, default=None)

	argparser.add_argument('--install-target', metavar='TARGET',
		action='append', dest='install_targets',
		type=str, default=[])
	argparser.add_argument('--install-component', metavar='COMPONENT',
		action='append', dest='install_components',
		type=str, default=[])

	options = argparser.parse_args()

	if options.scripts_dir is not None:
		script_common.irods_script_dir = options.scripts_dir
	script_common.augment_module_search_paths()

	script_common.init_logging(l, options.verbosity)
	script_common.setup_stacktrace_signal()

	pprint(vars(options))

	if path.exists(options.work_dir):
		shutil.rmtree(options.work_dir)
	os.mkdir(options.work_dir)

	pkg_dir = path.join(options.work_dir, 'pkg')
	os.mkdir(pkg_dir)

	icommands_paths = prepare_icommands(options, pkg_dir)
	iruntime_paths = prepare_irods_runtime(options, pkg_dir)

	# TODO:
	# 1. Prepare irods extenrs
	#    Start with direct dependencies of prepared binaries.
	#    Work down the tree, stripping before evaluating each next set.
	#    Use lief to identify direct dependencies and ldd to locate them.
	# 2. Prepare distro-provided externs
	#    Generally speaking, distro-provided libraries will already be stripped,
	#    but on the off chance that the build environment is funky, we should still follow the
	#    same pattern as irods externs
	# 3. Set runpath of all prepared binaries

	create_tarball(pkg_dir)

if __name__ == "__main__":
	sys.exit(_main())



