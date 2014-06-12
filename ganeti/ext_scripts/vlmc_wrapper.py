#!/usr/bin/env python

# Copyright (C) 2013 Greek Research and Technology Network
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

from archipelago.common import Error, DEVICE_PREFIX, loadrc
from archipelago import vlmc as vlmc


def ReadEnv():
    """Read the enviromental variables"""
    name = os.getenv("VOL_NAME")
    if name is None:
        sys.stderr.write('The environment variable VOL_NAME is missing.\n')
        return None

    return {"name": name,
            "size": os.getenv("VOL_SIZE"),
            "origin": os.getenv("EXTP_ORIGIN"),
            "snapshot_name": os.getenv("VOL_SNAPSHOT_NAME"),
            }


def create(env):
    """Create a new vlmc Image"""
    name = env.get("name")
    size = env.get("size")
    origin = env.get("origin")
    sys.stderr.write("Creating volume '%s' of size '%s' from '%s'\n"
                     % (name, size, origin))
    vlmc.create(name=name, size=int(size), snap=origin)
    return 0


def snapshot(env):
    """Create a snapshot of an existing vlmc Image."""
    name = env.get("name")
    snapshot_name = env.get("snapshot_name")
    sys.stderr.write("Creating snapshot '%s' from '%s'\n" %
                     (snapshot_name, name))
    vlmc.snapshot(name=name, snap_name=snapshot_name)
    return 0


def attach(env):
    """Map an existing vlmc Image to a block device

    This function maps an existing vlmc Image to a block device
    e.g. /dev/xsegbd{X} and returns the device path. If the mapping
    already exists, it returns the corresponding device path.

    """

    name = env.get("name")

    # Check if the mapping already exists
    d_id = vlmc.is_mapped(name)
    if d_id is not None:
      # The mapping exists. Return it.
        sys.stdout.write("%s" % str(DEVICE_PREFIX + str(d_id)))
        return 0
    # The mapping doesn't exist. Create it.
    d_id = vlmc.map_volume(name=name)
    # The device was successfully mapped. Return it.
    #maybe assert (d_id == vlmc.is_mapped(name)
    sys.stdout.write("%s" % str(DEVICE_PREFIX + str(d_id)))
    return 0


def detach(env):
    """Unmap a vlmc device from the Image it is mapped to

    This function unmaps an vlmc device from the Image it is mapped to.
    It is idempotent if the mapping doesn't exist at all.

    """
    name = env.get("name")

    #try:
    # Check if the mapping already exists
    d_id = vlmc.is_mapped(name)
    if d_id is not None:
        # The mapping exists. Unmap the vlmc device.
        vlmc.unmap_volume(name=str(DEVICE_PREFIX + str(d_id)))
    #assert(vlmc.is_mapped(name) == None)
    return 0
    #except Error as e:
    #  sys.stderr.write(str(e)+'\n')
    #  return -1


def grow(env):
    """Grow an existing vlmc Image"""
    name = env.get("name")
    size = env.get("size")

    sys.stderr.write("Resizing '%s'. New size '%s'\n" % (name, size))
    vlmc.resize(name=name, size=int(size))
    return 0


def remove(env):
    """Delete a vlmc Image"""
    name = env.get("name")

    sys.stderr.write("Deleting '%s'\n" % name)
    vlmc.remove(name=name)
    return 0


def verify(env):
    return 0


def setinfo(env):
    return 0


def main():
    env = ReadEnv()
    if env is None:
        sys.stderr.write("Wrong environment. Aborting...\n")
        return 1

    loadrc(None)

    actions = {
        'create': create,
        'snapshot': snapshot,
        'attach': attach,
        'detach': detach,
        'grow': grow,
        'remove': remove,
        'verify': verify,
        'setinfo': setinfo,
    }

    try:
        action_name = os.path.basename(sys.argv[0])
        action = actions[action_name]
        return action(env)
    except KeyError:
        sys.stderr.write("Action '%s' not supported\n" % action_name)
        return 1
    except Error as e:
        sys.stderr.write("Archipelago error: %s\n" % e)
        return 1

if __name__ == "__main__":
    sys.exit(main())
