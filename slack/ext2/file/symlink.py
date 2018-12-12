#!/usr/bin/env python
"""
Defines the symbolic link class used by the ext2 module.
"""
__license__ = "BSD"
__copyright__ = "Copyright 2013, Michael R. Falcone"


from struct import unpack_from
from ..error import *
from .file import Ext2File


class Ext2Symlink(Ext2File):
  """Represents a symbolic link to a file or directory on the Ext2 filesystem."""

  @property
  def isSymlink(self):
    """Gets whether the file object is a symbolic link."""
    return True
  
  def __init__(self, dirEntry, inode, fs):
    """Constructs a new symbolic link object from the specified directory entry."""
    super(Ext2Symlink, self).__init__(dirEntry, inode, fs)
    if (self._inode.mode & 0xA000) != 0xA000:
      raise FilesystemError("Inode does not point to a symbolic link.")


  def getLinkedPath(self):
    """Gets the file path linked to by this symbolic link."""
    if self._inode.size <= 60:
      path = self._inode.getStringFromBlocks()
    else:
      pathBytes = self._fs._readBlock(self._inode.lookupBlockId(0), 0, self._inode.size)
      path = unpack_from("<{0}s".format(self._inode.size), pathBytes)
    
    return path
  