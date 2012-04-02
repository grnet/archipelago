#!/usr/bin/env python
#
# Copyright (C) 2011 Greek Research and Technology Network
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.

""" vlmc provider wrapper-script for ganeti extstorage disk template

The script takes it's input from environment variables. Specifically the
following variables should be present:

 - VOL_NAME: The name of the new Image file
 - VOL_SIZE: The size of the new Image (in megabytes)

The following variables are optional:

 - EXTP_ORIGIN: The name of the Image file to snapshot

The code branches to the correct function, depending on the name (sys.argv[0])
of the executed script (attach, create, etc).

Returns O after successfull completion, 1 on failure

"""

import os
import sys

from ganeti import utils


def ReadEnv():
  """Read the enviromental variables
  """

  name = os.getenv("VOL_NAME")
  if name is None:
    sys.stderr.write('The environment variable VOL_NAME is missing.\n')
    return None

  size = os.getenv("VOL_SIZE")
  if size is None:
    sys.stderr.write('The environment variable VOL_SIZE is missing.\n')
    return None

  origin = os.getenv("EXTP_ORIGIN")

  return (name, size, origin)

def create(env):
  """Create a new vlmc Image
  """
  sys.stderr.write('Creation started...\n')

  name, size, origin = env

  cmd = ["vlmc", "create", "%s" % name, "--size", "%s" % size]
  if origin:
     cmd.extend(["--snap", origin])

  sys.stderr.write('Before RunCmd')
  result = utils.RunCmd(cmd)
  sys.stderr.write('After RunCmd')

  if result.failed:
    sys.stderr.write('vlmc creation failed (%s): %s\n' %
                     (result.fail_reason, result.output))
    return 1 

  return 0

def _ParseVlmcShowmappedOutput(output, volume_name):
  """Parse the output of `vlmc showmapped'.

  This method parses the output of `vlmc showmapped' and returns
  the vlmc block device path (e.g. /dev/xsegbd0) that matches the
  given vlmc volume.

  """
  allfields = 5
  volumefield = 2
  devicefield = 4

  field_sep = "\t"

  lines = output.splitlines()
  splitted_lines = map(lambda l: l.split(field_sep), lines)

  # Check empty output.
  if not splitted_lines:
    sys.stderr.write("vlmc showmapped returned empty output")
    sys.exit(1)

  # Check showmapped header line, to determine number of fields.
  field_cnt = len(splitted_lines[0])
  if field_cnt != allfields:
    sys.stderr.write("Cannot parse vlmc showmapped output because its format"
                " seems to have changed; expected %s fields, found %s",
                allfields, field_cnt)
    sys.exit(1)

  matched_lines = \
    filter(lambda l: len(l) == allfields and l[volumefield] == volume_name,
           splitted_lines)

  if len(matched_lines) > 1:
    sys.stderr.write("The vlmc volume %s is mapped more than once."
                " This shouldn't happen, try to unmap the extra"
                " devices manually.", volume_name)
    sys.exit(1) 

  if matched_lines:
    # vlmc block device found. Return it.
    dev = matched_lines[0][devicefield]
    return dev

  # The given volume is not mapped.
  return None

def attach(env):
  """Map an existing vlmc Image to a block device

  This function maps an existing vlmc Image to a block device
  e.g. /dev/xsegbd{X} and returns the device path. If the mapping
  already exists, it returns the corresponding device path.
  """

  name, _, _ = env

  # Check if the mapping already exists
  cmd = ["vlmc", "showmapped"]
  result = utils.RunCmd(cmd)
  if result.failed:
    sys.stderr.write("vlmc showmapped failed (%s): %s" %
                     (result.fail_reason, result.output))
    return 1

  dev = _ParseVlmcShowmappedOutput(result.output, name)
  if dev:
    # The mapping exists. Return it.
    return dev

  # The mapping doesn't exist. Create it.
  map_cmd = ["vlmc", "map", name]
  result = utils.RunCmd(map_cmd)
  if result.failed:
    sys.stderr.write("vlmc map failed (%s): %s",
                result.fail_reason, result.output)
    return 1

  # Find the corresponding vlmc device.
  showmap_cmd = ["vlmc", "showmapped"]
  result = utils.RunCmd(showmap_cmd)
  if result.failed:
    sys.stderr.write("vlmc map succeeded, but showmapped failed (%s): %s",
                result.fail_reason, result.output)
    return 1

  dev = self._ParseRbdShowmappedOutput(result.output, name)

  if not dev:
    sys.stderr.write("vlmc map succeeded, but could not find the vlmc block"
                " device in output of showmapped, for volume: %s", name)

  # The device was successfully mapped. Return it.
  return dev

def detach(env):
  """Unmap a vlmc device from the Image it is mapped to

  This function unmaps an vlmc device from the Image it is mapped to.
  It is idempotent if the mapping doesn't exist at all.
  """
  name, _, _ = env

  # Check if the mapping already exists
  cmd = ["vlmc", "showmapped"]
  result = utils.RunCmd(cmd)
  if result.failed:
    sys.stderr.write("vlmc showmapped failed (%s): %s" %
                     (result.fail_reason, result.output))
    return 1

  dev = _ParseVlmcShowmappedOutput(result.output, name)

  if dev:
    # The mapping exists. Unmap the vlmc device.
    unmap_cmd = ["vlmc", "unmap", "%s" % dev]
    result = utils.RunCmd(unmap_cmd)
    if result.failed:
      sys.stderr.write("vlmc unmap failed (%s): %s",
                  result.fail_reason, result.output)

  return 0

def grow(env):
  """Grow an existing vlmc Image
  """
  name, size, _ = env

  cmd = ["vlmc", "resize", "%s" % name, "--size", "%s" % size]

  result = utils.RunCmd(cmd)
  if result.failed:
    sys.stderr.write('vlmc resize failed (%s): %s\n' %
                     (result.fail_reason, result.output))
    return 1

  return 0

def remove(env):
  """ Delete a vlmc Image
  """

  name, _, _ = env

  cmd = ["vlmc", "rm", "%s" % name]

  result = utils.RunCmd(cmd)
  if result.failed:
    sys.stderr.write("Can't remove Image %s from cluster with vlmc rm: "
                     "%s - %s" % 
                     (name, result.fail_reason, result.output))
    return 1

  return 0

def verify(env):
  return 0

def main():
  env = ReadEnv()
  if env is None:
    sys.stderr.write("Wrong environment. Aborting...\n")
    return 1

  try:
    return {
      'attach': attach(env),
      'create': create(env),
      'detach': detach(env),
      'grow'  : grow(env),
      'remove': remove(env),
      'verify': verify(env),
    }[os.path.basename(sys.argv[0])]
  except:
    sys.stderr.write("Op not supported")
    return 1

if __name__ == "__main__":
    sys.exit(main())
