#!/usr/bin/env python
"""
Defines classes and functions for directory object of the ext2 module.
"""
__license__ = "BSD"
__copyright__ = "Copyright 2013, Michael R. Falcone"


import re
from struct import pack, unpack_from
from time import time
from ..error import *
from .file import Ext2File
from .symlink import Ext2Symlink
from .regularfile import Ext2RegularFile


def _openRootDirectory(fs):
  """Opens and returns the root directory of the specified filesystem."""
  return Ext2Directory._openEntry(None, fs)


class _EntryList(object):
  """Represents a doubly-liked directory list in the Ext2 filesystem. For internal use only."""
  
  def __init__(self, containingDir):
    """Constructs a new directory entry list for the specified directory."""
    self._containingDir = containingDir
    self._entries = []
    prevEntry = None
    for i in range(containingDir.numBlocks):
      blockId = containingDir._inode.lookupBlockId(i)
      if blockId == 0:
        break
      blockBytes = containingDir._fs._readBlock(blockId)
      offset = 0
      while offset < containingDir._fs.blockSize:
        entry = _Entry(i, blockId, offset, prevEntry, blockBytes[offset:], containingDir)
        if entry.inodeNum == 0:
          break
        prevEntry = entry
        offset += entry.size
        self._entries.append(entry)
  
  
  def __iter__(self):
    """Gets the iterator to this list."""
    self._itIndex = 0
    return self
  
  
  def next(self):
    """Gets the next entry in the linked list."""
    if self._itIndex == len(self._entries):
      raise StopIteration
    entry = self._entries[self._itIndex]
    self._itIndex += 1
    return entry
  
  
  def append(self, name, inode):
    """Appends a new entry for the specified inode at the end of the list, and returns
    the entry object."""
    
    nameLength = len(name)
    if nameLength > 255:
      raise FilesystemError("Name is too long.")
    if not nameLength > 0:
      raise FilesystemError("Name is too short.")

    lastEntry = self._entries[-1]

    entrySize = nameLength + 7

    # if new entry doesn't fit on current block, allocate a new one
    if entrySize + lastEntry._offset + len(lastEntry.name) + 11 < self._containingDir._fs.blockSize:
      entryBlockIndex = lastEntry._bindex
      entryBlockId = lastEntry._bid
      lastSize = len(lastEntry.name) + 11 # 7 bytes for record base, 4 bytes for alignment
      lastSize -= lastSize % 4 # align to 4 bytes
      entryOffset = lastEntry._offset + lastSize
      entrySize = self._containingDir._fs.blockSize - entryOffset
    else:
      entryBlockId = self._containingDir._fs._allocateBlock(True)
      entryBlockIndex = self._containingDir._inode.assignNextBlockId(entryBlockId)
      self._containingDir._inode.size += self._containingDir._fs.blockSize
      entryOffset = 0
      entrySize = self._containingDir._fs.blockSize
    
    fileType = 0
    if self._containingDir._fs._superblock.revisionMajor > 0:
      if (inode.mode & 0x4000) == 0x4000:
        fileType = 2
      elif (inode.mode & 0xA000) == 0xA000:
        fileType = 7
      elif (inode.mode & 0x8000) == 0x8000:
        fileType = 1
    
    byteString = pack("<IHBB{0}s".format(nameLength), inode.number, entrySize, nameLength, fileType, name)
    self._containingDir._fs._writeToBlock(entryBlockId, entryOffset, byteString)
    newEntry = _Entry(entryBlockIndex, entryBlockId, entryOffset, None, byteString, self._containingDir)
    newEntry.nextEntry = None
    newEntry.prevEntry = lastEntry
    lastEntry.nextEntry = newEntry
    self._entries.append(newEntry)
    return newEntry
  
  
  def remove(self, entry):
    """Removes the specified directory from the entry list."""
    self._entries.remove(entry)
    entry.inodeNum = 0
    entry.prevEntry.nextEntry = entry.nextEntry
    if entry.nextEntry:
      entry.nextEntry.prevEntry = entry.prevEntry



class _Entry(object):
  """Represents a directory entry in a linked entry list on the Ext2 filesystem. For internal use only."""

  @property
  def size(self):
    """Gets the size of this entry in bytes."""
    return self._size

  @property
  def containingDir(self):
    """Gets the directory object that contains this entry."""
    return self._containingDir
  
  @property
  def name(self):
    """Gets the name of the file represented by this entry."""
    return self._name

  @property
  def inodeNum(self):
    """Gets the inode number of the file represented by this entry."""
    return self._inodeNum
  @inodeNum.setter
  def inodeNum(self, value):
    """Sets the inode number of the file represented by this entry."""
    self._inodeNum = value
    self.__writeData(0, pack("<I", self._inodeNum))

  @property
  def prevEntry(self):
    """Gets the previous entry in the list."""
    return self._prevEntry
  @prevEntry.setter
  def prevEntry(self, value):
    """Sets the previous entry in the list."""
    self._prevEntry = value
  
  @property
  def nextEntry(self):
    """Gets the next entry in the list."""
    return self._nextEntry
  @nextEntry.setter
  def nextEntry(self, value):
    """Sets the next entry in the list."""
    if value is None:
      if self.size + self._offset + 4 <= self._containingDir._fs.blockSize:
        self.__writeData(self.size, pack("<I", 0))
    else:
      if value._bindex == self._bindex:
        newSize = value._offset - self._offset
        if not newSize > 0:
          raise FilesystemError("Next entry not after previous entry.")
      else:
        newSize = self._containingDir._fs.blockSize - self._offset + value._offset
      self.__writeData(4, pack("<H", newSize))
    self._nextEntry = value

  
  def __init__(self, blockIndex, blockId, blockOffset, prevEntry, byteString, containingDir):
    """Contructs a new entry in the linked list."""
    
    if containingDir._fs._superblock.revisionMajor == 0:
      fields = unpack_from("<IHH", byteString)
      self._fileType = 0
    else:
      fields = unpack_from("<IHBB", byteString)
      self._fileType = fields[3]
    
    self._name = unpack_from("<{0}s".format(fields[2]), byteString, 8)[0]
    self._inodeNum = fields[0]
    self._size = fields[1]
    self._bindex = blockIndex
    self._bid = blockId
    self._offset = blockOffset
    self._containingDir = containingDir
    self._nextEntry = None
    self._prevEntry = prevEntry
    if not (self._inodeNum == 0 or self._prevEntry is None):
      self._prevEntry._nextEntry = self
  
  
  def __writeData(self, offset, byteString):
    """Writes the specified byte string to the offset within the entry."""
    self._containingDir._fs._writeToBlock(self._bid, self._offset + offset, byteString)

    




class Ext2Directory(Ext2File):
  """Represents a directory on the Ext2 filesystem."""

  @property
  def isDir(self):
    """Gets whether the file object is a directory."""
    return True


  def __init__(self, dirEntry, inode, fs):
    """Constructs a new directory object from the specified directory entry."""
    super(Ext2Directory, self).__init__(dirEntry, inode, fs)
    if (self._inode.mode & 0x4000) != 0x4000:
      raise FilesystemError("Inode does not point to a directory.")
    self._entryList = _EntryList(self)



  @classmethod
  def _openEntry(cls, dirEntry, fs):
    """Opens and returns the file object described by the specified directory entry."""
    if dirEntry:
      assert dirEntry.inodeNum != 0
      inode = fs._readInode(dirEntry.inodeNum)
    else:
      inode = fs._readInode(2)
    
    if (inode.mode & 0x4000) == 0x4000:
      return Ext2Directory(dirEntry, inode, fs)
    if (inode.mode & 0xA000) == 0xA000:
      return Ext2Symlink(dirEntry, inode, fs)
    if (inode.mode & 0x8000) == 0x8000:
      return Ext2RegularFile(dirEntry, inode, fs)

    return Ext2File(dirEntry, inode, fs)



  def files(self):
    """Generates a list of files in the directory."""
    for entry in self._entryList:
      yield Ext2Directory._openEntry(entry, self._fs)



  def getFileAt(self, relativePath, followSymlinks = False):
    """Looks up and returns the file specified by the relative path from this directory. Raises a
    FileNotFoundError if the file cannot be found."""
    
    pathParts = re.compile("/+").split(relativePath)
    if len(pathParts) > 1 and pathParts[0] == "":
      del pathParts[0]
    if len(pathParts) > 1 and pathParts[-1] == "":
      del pathParts[-1]
    if len(pathParts) == 0:
      raise FileNotFoundError()
    if len(pathParts[0]) == 0:
      return self
    
    curFile = self
    for curPart in pathParts:
      if curFile.isDir:
        found = False
        for entry in curFile._entryList:
          if entry.name == curPart:
            curFile = Ext2Directory._openEntry(entry, self._fs)
            while curFile.isSymlink and followSymlinks:
              linkedPath = curFile.getLinkedPath()
              if linkedPath.startswith("/"):
                curFile = self._fs.rootDir.getFileAt(linkedPath[1:])
              else:
                curFile = curFile.parentDir.getFileAt(linkedPath)
            found = True
            break
        if not found:
          raise FileNotFoundError()
    
    if curFile.absolutePath == self.absolutePath:
      return self
    
    return curFile



  def removeFile(self, rmFile):
    """Removes the specified file from the directory. If the file object is a non-empty
    directory, an error is raised."""
    
    if rmFile.name == "." or rmFile.name == "..":
      raise FilesystemError("Invalid directory name.")
    
    if rmFile.isDir:
      numFiles = 0
      for f in rmFile.files():
        numFiles += 1
        if numFiles > 2:
          raise FilesystemError("Directory not empty.")
      if rmFile.parentDir is rmFile:
        raise FilesystemError("Cannot delete root directory.")

    if not rmFile.parentDir is self:
      raise FilesystemError("File or directory does not exist in the current directory.")

    self._entryList.remove(rmFile._dirEntry)
    if rmFile.isDir:
      self._inode.numLinks -= 1
      rmFile._inode.numLinks -= 2
    else:
      rmFile._inode.numLinks -= 1
    
    if rmFile._inode.numLinks <= 0:
      if not rmFile.isSymlink or rmFile._inode.size > 60:
        for bid in rmFile._inode.usedBlocks():
          self._fs._freeBlock(bid)
      rmFile._inode.free()



  def moveFile(self, fromFile, toDir, newFilename = None):
    """Moves the specified file to the specified directory with the optional new name."""
    if newFilename:
      name = newFilename
    else:
      name = fromFile.name
    toDir.__validateName(name)
    
    oldEntry = fromFile._dirEntry
    oldParent = fromFile.parentDir
    fromFile._dirEntry = toDir._entryList.append(name, fromFile._inode)
    fromFile._parentDir = toDir
    oldParent._entryList.remove(oldEntry)
    
    if fromFile.isDir:
      oldParent._inode.numLinks -= 1
      fromFile.parentDir._inode.numLinks += 1
      for entry in fromFile._entryList:
        if entry.name == "..":
          entry.inodeNum = fromFile.parentDir._inode.number
          break




  def makeDirectory(self, name, uid = None, gid = None):
    """Creates a new directory in this directory and returns the new file object."""
    
    if uid is None:
      uid = self.uid
    if gid is None:
      gid = self.gid
    
    mode = 0
    mode |= 0x4000 # set directory
    mode |= 0x0100 # user read
    mode |= 0x0080 # user write
    mode |= 0x0040 # user execute
    mode |= 0x0020 # group read
    mode |= 0x0008 # group execute
    mode |= 0x0004 # others read
    mode |= 0x0001 # others execute
    
    entry = self.__makeNewEntry(name, mode, uid, gid, True)
    defaultEntries = pack("<IHBB1s3xIHBB2s", entry.inodeNum, 12, 1, 2, ".", self._inode.number, self._fs.blockSize-12, 2, 2, "..")
    self._inode.numLinks += 1
    inode = self._fs._readInode(entry._inodeNum)
    inode.numLinks += 1
    inode.size += self._fs.blockSize
    self._fs._writeToBlock(inode.lookupBlockId(0), 0, defaultEntries)
    return Ext2Directory._openEntry(entry, self._fs)



  def makeRegularFile(self, name, uid = None, gid = None, creationTime = None, modTime = None, accessTime = None, permissions = None):
    """Creates a new regular file in this directory and returns the new file object."""
    
    if uid is None:
      uid = self.uid
    if gid is None:
      gid = self.gid
    
    if not permissions:
      mode = 0
      mode |= 0x0100 # user read
      mode |= 0x0080 # user write
      mode |= 0x0040 # user execute
      mode |= 0x0020 # group read
      mode |= 0x0008 # group execute
      mode |= 0x0004 # others read
      mode |= 0x0001 # others execute
    else:
      mode = permissions
    mode |= 0x8000 # set regular file

    entry = self.__makeNewEntry(name, mode, uid, gid, False, creationTime, modTime, accessTime)
    return Ext2Directory._openEntry(entry, self._fs)



  def makeHardLink(self, name, linkedFile):
    """Creates a new hard link in this directory to the given file object and returns the new file object."""
    self.__validateName(name)
    inode = linkedFile._inode
    entry = self._entryList.append(name, inode)
    inode.numLinks += 1
    return Ext2Directory._openEntry(entry, self._fs)



  def makeSymbolicLink(self, name, linkedPath, uid = None, gid = None):
    """Creates a new symbolic link in this directory to the specified path
    and returns the new file object."""
    if uid is None:
      uid = self.uid
    if gid is None:
      gid = self.gid
      
    mode = 0
    mode |= 0xA000 # set symbolic link
    mode |= 0x0100 # user read
    mode |= 0x0080 # user write
    mode |= 0x0040 # user execute
    mode |= 0x0020 # group read
    mode |= 0x0008 # group execute
    mode |= 0x0004 # others read
    mode |= 0x0001 # others execute
    
    size = len(linkedPath)
    if size <= 60:
      entry = self.__makeNewEntry(name, mode, uid, gid, False)
    else:
      entry = self.__makeNewEntry(name, mode, uid, gid, True)
    
    inode = self._fs._readInode(entry._inodeNum)
    inode.size = size

    if size <= 60:
      inode.assignStringToBlocks(linkedPath)
    else:
      # only support allocating single block for max symlink path length of the block size
      self._fs._writeToBlock(inode.lookupBlockId(0), 0, pack("<{0}s".format(size), linkedPath))
    
    return Ext2Directory._openEntry(entry, self._fs)



  def __validateName(self, name):
    """Validates the specified name and returns successfully if valid."""
    
    if len(name.strip()) == 0:
      raise FilesystemError("No name specified.")

    if len(name) > 255:
      raise FilesystemError("Specified name is too long.")

    if name == "." or name == "..":
      raise FilesystemError("Invalid name specified.")

    if "/" in name or "\0" in name:
      raise FilesystemError("Name contains invalid characters.")

    # make sure destination does not already exist
    for entry in self._entryList:
      if entry.name == name:
        raise FilesystemError("An entry with that name already exists.")



  def __makeNewEntry(self, name, mode, uid, gid, allocateBlock, creationTime = None, modTime = None, accessTime = None):
    """Creates a new entry with the given parameters and returns the new object."""
    curTime = int(time())
    if creationTime is None:
      creationTime = curTime
    if modTime is None:
      modTime = curTime
    if accessTime is None:
      accessTime = curTime
    
    self.__validateName(name)
    
    inode = self._fs._allocateInode(mode, uid, gid, creationTime, modTime, accessTime)
    if allocateBlock:
      bid = self._fs._allocateBlock(True)
      inode.assignNextBlockId(bid)
    
    entry = self._entryList.append(name, inode)
    inode.numLinks += 1
    
    return entry
