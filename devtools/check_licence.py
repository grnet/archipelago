#!/usr/bin/env python

# Copyright 2013 GRNET S.A. All rights reserved.
#
# Redistribution and use in source and binary forms, with or
# without modification, are permitted provided that the following
# conditions are met:
#
#   1. Redistributions of source code must retain the above
#      copyright notice, this list of conditions and the following
#      disclaimer.
#
#   2. Redistributions in binary form must reproduce the above
#      copyright notice, this list of conditions and the following
#      disclaimer in the documentation and/or other materials
#      provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY GRNET S.A. ``AS IS'' AND ANY EXPRESS
# OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL GRNET S.A OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
# USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# The views and conclusions contained in the software and
# documentation are those of the authors and should not be
# interpreted as representing official policies, either expressed
# or implied, of GRNET S.A.


import os, sys, shutil

EXCLUDE_FILENAMES = ['.gitignore', 'README', 'version', 'c_bsd.licence',
                     'python_bsd.licence', 'devflow.conf', 'verify',
                     'create', 'detach', 'attach', 'parameters.list', 'grow',
                     'remove', 'python_gpl.licence', 'c_gpl.licence', 'tags',
                     'config.env', 'distribute_setup.py', '.o', '.ko', '.mod',
		     '.a', '.so', '.cmd', '.mod.c', '.pyc', 'version.py']
GPL_FILES = ['vlmc_wrapper.py', 'kernel/xseg_posix.c', 'kernel/xseg_pthread.c',
             'xsegbd.c']
EXCLUDE_DIRECTORIES = ['.git', 'doc', 'archipelago.egg-info', 'xseg.egg-info']
VALID_YEARS = [2011, 2012, 2013]
CUR_YEAR = 2013
PYTHON_INTERPRETER = "#!/usr/bin/env python\n"
BASH_INTERPRETER = "#!/bin/bash\n"
THIS_PATH = os.path.dirname(os.path.realpath(__file__))
PYTHON_BSD_LICENCE = open(os.path.join(THIS_PATH, "python_bsd.licence")).readlines()
PYTHON_GPL_LICENCE = open(os.path.join(THIS_PATH, "python_gpl.licence")).readlines()
C_BSD_LICENCE = open(os.path.join(THIS_PATH, "c_bsd.licence")).readlines()
C_GPL_LICENCE = open(os.path.join(THIS_PATH, "c_gpl.licence")).readlines()


class InvalidTypeException(Exception):
    """Exception to raise for invalid type"""
    pass

class LicenceException(Exception):
    """Exception to raise for licence exception"""
    pass

class ExcludedFileException(Exception):
    """Exception to raise for excluded file"""
    pass

class EmptyFileException(Exception):
    """Exception to raise for empty file"""
    pass

class PartialLicenceException(Exception):
    """exception to raise for partial licence"""
    pass

class NoLicenceException(Exception):
    """Exception to raise for no licence"""
    pass

class NoInterpreterException(Exception):
    """Esception to raise when no interpreter found"""
    pass


def get_file_type(filename):
    """Return a string with the type of the file"""
    for excl_file in EXCLUDE_FILENAMES:
        if filename.endswith(excl_file):
            raise ExcludedFileException(filename)

    if filename.endswith('.c') or filename.endswith('.h'):
        return 'c'
    elif filename.endswith('.sh'):
        return 'bash'
    elif filename.endswith('.py'):
        return 'python'
    elif filename.endswith('Makefile') or filename.endswith('.mk'):
        return 'makefile'

    firstline = open(filename).readline()
    if firstline == BASH_INTERPRETER:
        return 'bash'
    if firstline == PYTHON_INTERPRETER:
        return 'python'

    raise InvalidTypeException(file)


def __check_licence(filename, licence, year_line, interpreter = None):
    """Generic test licence function"""
    fil = open(filename)
    line = fil.readline()
    if line == "":
        raise EmptyFileException("Empty file")

    if interpreter:
        if line == interpreter:
            line = fil.readline()
            if line != "\n":
                raise Exception("Blank line is expected after %s",
                        interpreter)
            line = fil.readline()
#        else:
#            raise NoInterpreterException("No interpreter found")

    if line == "":
        raise EmptyFileException("Empty file")

    if year_line > 0:
        for i in range(0, year_line):
            if line != licence[i]:
                raise NoLicenceException("No licence")
            line = fil.readline()
    found = False
    for valid_year in VALID_YEARS:
        licence_line = licence[year_line].replace("#YEAR#", str(valid_year))
        if line == licence_line:
            found = True
            break
    if not found:
        raise NoLicenceException("No licence")
    line = fil.readline()
    for licence_line in licence[year_line + 1:]:
        if licence_line != line:
            print "   Found: " + line
            print "Expected: " + licence_line
            raise PartialLicenceException("Partial licence found")
        line = fil.readline()


def __check_licence2(filename, licence, year_line, interpreter = None,
                     insert = False):
    """Generic test or insert licence function"""
    try:
        __check_licence(filename, licence, year_line, interpreter)
    except NoLicenceException:
        if insert:
            fil = open(filename)
            new_filename = filename + '.tmp'
            new_fil = open(new_filename, 'w')
            line = fil.readline()
            if interpreter:
                if line == interpreter:
                    new_fil.write(line)
                    line = fil.readline()
                    new_fil.write(line) #mustbe "" otherwise Blankline exception
                    line = fil.readline()
            if year_line > 0:
                for i in range(0, year_line):
                    new_fil.write(licence[i])
            new_fil.write(licence[year_line].replace("#YEAR#", str(CUR_YEAR)))
            for licence_line in licence[year_line+1:]:
                new_fil.write(licence_line)
            new_fil.write("\n")
            while line != "":
                new_fil.write(line)
                line = fil.readline()
            os.remove(filename)
            shutil.move(new_filename, filename)

        else:
            raise NoLicenceException("No licence")



def check_licence_python(filename, insert = False):
    """Check or insert licence in python files"""
    licence = PYTHON_BSD_LICENCE
    for gplfile in GPL_FILES:
        if filename.endswith(gplfile):
            licence = PYTHON_GPL_LICENCE
    __check_licence2(filename, licence, 0, PYTHON_INTERPRETER, insert)


def check_licence_bash(filename, insert = False):
    """Check or insert licence for bash files"""
    __check_licence2(filename, PYTHON_BSD_LICENCE, 0, BASH_INTERPRETER, insert)


def check_licence_makefile(filename, insert = False):
    """Check or insert licence for makefiles files"""
    __check_licence2(filename, PYTHON_BSD_LICENCE, 0, insert = insert)


def check_licence_c(filename, insert = False):
    """Check or insert licence for c files"""
    licence = C_BSD_LICENCE
    for gplfile in GPL_FILES:
        if filename.endswith(gplfile):
            licence = C_GPL_LICENCE

    __check_licence2(filename, licence, 1, insert = insert)


if __name__ == "__main__":
    try:
        root_dir = sys.argv[1]
    except:
        print "Usage: %s path [--insert]" % sys.argv[0]
        exit(1)
    try:
        do_insert = sys.argv[2] == '--insert'
    except:
        do_insert = False

    for directory, subdirectories, files in os.walk(root_dir):
        for ed in EXCLUDE_DIRECTORIES:
            if ed in subdirectories:
                subdirectories.remove(ed)
        for filen in files:
            full_path = os.path.join(directory, filen)
            try:
                ft = get_file_type(full_path)
                {
                'c': check_licence_c,
                'python': check_licence_python,
                'bash': check_licence_bash,
                'makefile': check_licence_makefile
                }[ft](full_path, do_insert)
            except ExcludedFileException:
                pass
            except InvalidTypeException:
                print "Invalid type: ", full_path
            except Exception as e:
                print e, " ", full_path
