#!/usr/bin/env python
"""
Defines the base file class used by the ext2 module.
"""
__license__ = "BSD"
__copyright__ = "Copyright 2013, Michael R. Falcone"


from time import localtime, strftime
from ..error import *


class Ext2File(object):
  """Represents a file or directory on the Ext2 filesystem."""

  @property
  def fsType(self):
    """Gets a string representing the filesystem type."""
    return self._fs.fsType

  @property
  def name(self):
    """Gets the name of this file on the filesystem."""
    return self._name

  @property
  def absolutePath(self):
    """Gets the absolute path to this file or directory, including the name if
    it is a file or symlink."""
    return self._path

  @property
  def inodeNum(self):
    """Gets the inode number of this file on the filesystem."""
    return self._inode.number

  @property
  def isValid(self):
    """Returns True if the inode of this file is in use, or False if it is not."""
    return self._inode.isUsed

  @property
  def isDir(self):
    """Gets whether the file object is a directory."""
    return False

  @property
  def isRegular(self):
    """Gets whether the file object is a regular file."""
    return False

  @property
  def isSymlink(self):
    """Gets whether the file object is a symbolic link."""
    return False

  @property
  def isExecutable(self):
    """Gets whether the file object is executable."""
    return (self._inode.mode & 0x49) != 0 # return true if any executable flag is set

  @property
  def modeStr(self):
    """Gets a string representing the file object's mode."""
    return "".join(self._modeStr)

  @property
  def numLinks(self):
    """Gets the number of hard links to this file object."""
    return self._inode.numLinks

  @property
  def size(self):
    """Gets the size of the file in bytes."""
    return self._inode.size

  @property
  def numBlocks(self):
    """Gets the number of blocks used for data in the file."""
    return self._inode.numDataBlocks

  @property
  def timeCreatedEpoch(self):
    """Gets the time and date the file was created as a UNIX epoch timestamp."""
    return self._inode.timeCreated

  @property
  def timeModifiedEpoch(self):
    """Gets the time and date the file was last modified as a UNIX epoch timestamp."""
    return self._inode.timeModified

  @property
  def timeAccessedEpoch(self):
    """Gets the time and date the file was last accessed as a UNIX epoch timestamp."""
    return self._inode.timeAccessed
  
  @property
  def timeCreated(self):
    """Gets the time and date the file was created as a string."""
    return strftime("%b %d %H:%M %Y", localtime(self._inode.timeCreated))

  @property
  def timeAccessed(self):
    """Gets the time and date the file was last accessed as a string."""
    return strftime("%b %d %H:%M %Y", localtime(self._inode.timeAccessed))

  @property
  def timeModified(self):
    """Gets the time and date the file was last modified as a string."""
    return strftime("%b %d %H:%M %Y", localtime(self._inode.timeModified))

  @property
  def parentDir(self):
    """Gets this file object's parent directory. The root directory's parent is itself."""
    return self._parentDir

  @property
  def permissions(self):
    """Gets this file object's permissions bitmap."""
    return (self._inode.mode & 0x1FF) # ignore everything but permissions
  @permissions.setter
  def permissions(self, value):
    """Sets this file object's permissions bitmap."""
    mode = self._inode.mode & 0xFE00 # save non-permission bits of current mode
    mode |= (value & 0x1FF) # set permission bits from new mode
    self._inode.mode = mode

  @property
  def uid(self):
    """Gets the uid of the file owner."""
    return self._inode.uid
  @uid.setter
  def uid(self, value):
    """Sets the uid of the file owner."""
    self._inode.uid = value

  @property
  def gid(self):
    """Gets the gid of the file owner."""
    return self._inode.gid
  @gid.setter
  def gid(self, value):
    """Sets the gid of the file owner."""
    self._inode.gid = value

  def __init__(self, dirEntry, inode, fs):
    """Constructs a new file object from the specified entry and inode."""
    self._fs = fs
    self._inode = inode
    self._dirEntry = dirEntry
    self._name = ""
    
    if self._dirEntry:
      self._name = self._dirEntry.name
      
    
    # resolve current/up directories
    if self._dirEntry:
      if self._name == ".":
        self._dirEntry = dirEntry.containingDir._dirEntry
      elif self._name == "..":
        self._dirEntry = dirEntry.containingDir.parentDir._dirEntry

    # determine absolute path to file
    if self._dirEntry:
      self._parentDir = self._dirEntry.containingDir
      if self._parentDir.absolutePath == "/":
        parentPath = ""
      else:
        parentPath = self._parentDir.absolutePath
      self._path = "{0}/{1}".format(parentPath, self._dirEntry.name)
    else:
      self._parentDir = self
      self._path = "/"
    
    if not self._parentDir.isDir:
      raise FilesystemError("Invalid parent directory.")
    

    self._modeStr = list("----------")
    if self.isDir:
      self._modeStr[0] = "d"
    elif self.isSymlink:
      self._modeStr[0] = "l"
    if (self._inode.mode & 0x0100) != 0:
      self._modeStr[1] = "r"
    if (self._inode.mode & 0x0080) != 0:
      self._modeStr[2] = "w"
    if (self._inode.mode & 0x0040) != 0:
      self._modeStr[3] = "x"
    if (self._inode.mode & 0x0020) != 0:
      self._modeStr[4] = "r"
    if (self._inode.mode & 0x0010) != 0:
      self._modeStr[5] = "w"
    if (self._inode.mode & 0x0008) != 0:
      self._modeStr[6] = "x"
    if (self._inode.mode & 0x0004) != 0:
      self._modeStr[7] = "r"
    if (self._inode.mode & 0x0002) != 0:
      self._modeStr[8] = "w"
    if (self._inode.mode & 0x0001) != 0:
      self._modeStr[9] = "x"
    
  
  def files(self):
    """Generates a list of files in the directory."""
    raise InvalidFileTypeError()


  def getFileAt(self, relativePath):
    """Looks up and returns the file specified by the relative path from this directory. Raises a
    FileNotFoundError if the file object cannot be found."""
    raise InvalidFileTypeError()

  def removeFile(self, rmFile):
    """Removes the specified file from the directory. If the file object is a non-empty
    directory, an error is raised."""
    raise InvalidFileTypeError()

  def makeDirectory(self, name, uid = None, gid = None):
    """Creates a new directory in this directory and returns the new file object."""


  def makeRegularFile(self, name, uid = None, gid = None, creationTime = None, modTime = None, accessTime = None):
    """Creates a new regular file in this directory and returns the new file object."""
    raise InvalidFileTypeError()


  def makeHardLink(self, name, linkedFile):
    """Creates a new hard link in this directory to the given file object and returns the new file object."""
    raise InvalidFileTypeError()


  def makeSymbolicLink(self, name, linkedFile, uid = None, gid = None):
    """Creates a new symbolic link in this directory to the given file object and returns the new file object."""
    raise InvalidFileTypeError()
  
  
  def blocks(self):
    """Generates a list of data blocks in the file."""
    raise InvalidFileTypeError()


  def write(self, byteString, position):
    """Writes the specified string of bytes to the specified position in the file, or at the end
    if no position is specified"""
    raise InvalidFileTypeError()


  def getLinkedPath(self):
    """Gets the file path linked to by this symbolic link."""
    
  
