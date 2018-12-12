#!/usr/bin/env python
"""
Defines the filesystem class used by the ext2 module.
"""
__license__ = "BSD"
__copyright__ = "Copyright 2013, Michael R. Falcone"


import inspect
from uuid import uuid4
from os import path, remove
from collections import deque
from struct import pack, unpack
from time import time
from math import ceil
from ..file.directory import _openRootDirectory
from ..error import FilesystemError
from .superblock import _Superblock
from .bgdt import _BGDT
from .inode import _Inode
from .device import _DeviceFromFile


class InformationReport(object):
  """Structure used to return information about the filesystem."""
  pass


class Ext2Filesystem(object):
  """Models a filesystem image file formatted to Ext2."""
  
  
  @property
  def fsType(self):
    """Gets a string representing the filesystem type. Always EXT2."""
    return "EXT2"
  
  @property
  def revision(self):
    """Gets the filesystem revision string formatted as MAJOR.MINOR."""
    if not self.isValid:
      raise FilesystemError("Filesystem is not valid.")
    return "{0}.{1}".format(self._superblock.revisionMajor, self._superblock.revisionMinor)
  
  @property
  def totalSpace(self):
    """Gets the total filesystem size in bytes."""
    if not self.isValid:
      raise FilesystemError("Filesystem is not valid.")
    return self._superblock.blockSize * self._superblock.numBlocks
  
  @property
  def freeSpace(self):
    """Gets the number of free bytes."""
    if not self.isValid:
      raise FilesystemError("Filesystem is not valid.")
    return self._superblock.blockSize * self._superblock.numFreeBlocks
  
  @property
  def usedSpace(self):
    """Gets the number of used bytes."""
    if not self.isValid:
      raise FilesystemError("Filesystem is not valid.")
    return self.totalSpace - self.freeSpace

  @property
  def totalFileSpace(self):
    """Gets the total number of bytes available for files."""
    if not self.isValid:
      raise FilesystemError("Filesystem is not valid.")
    bgdtBlocks = int(ceil(float(self._superblock.numBlockGroups * 32) / self._superblock.blockSize))
    inodeTableBlocks = int(ceil(float(self._superblock.numInodesPerGroup * self._superblock.inodeSize) / self._superblock.blockSize))
    numFileBlocks = (self._superblock.numBlocks - self._superblock.firstDataBlockId - inodeTableBlocks * self._superblock.numBlockGroups
                     - 2 * self._superblock.numBlockGroups - (1 + bgdtBlocks) * (len(self._superblock.copyLocations) + 1))
    return numFileBlocks * self._superblock.blockSize
  
  @property
  def blockSize(self):
    """Gets the block size in bytes."""
    if not self.isValid:
      raise FilesystemError("Filesystem is not valid.")
    return self._superblock.blockSize
  
  @property
  def numBlockGroups(self):
    """Gets the number of block groups."""
    if not self.isValid:
      raise FilesystemError("Filesystem is not valid.")
    return len(self._bgdt.entries)
  
  @property
  def numInodes(self):
    """Gets the total number of inodes."""
    if not self.isValid:
      raise FilesystemError("Filesystem is not valid.")
    return self._superblock.numInodes
  
  @property
  def rootDir(self):
    """Gets the file object representing the root directory."""
    if not self.isValid:
      raise FilesystemError("Filesystem is not valid.")
    return _openRootDirectory(self)

  @property
  def isValid(self):
    """Gets whether the filesystem is valid and mounted."""
    return self._isValid


  @classmethod
  def makeFromNewImageFile(cls, imageFilename, blockSize, numBlocks):
    """Creates a new Ext2 filesystem image with the specified image file name and
    the specfied number of blocks. The specified block size must be either 1024, 2048,
    or 4096."""
    if blockSize != 1024 and blockSize != 2048 and blockSize != 4096:
      raise FilesystemError("Invalid blocksize specified.")
    device = _DeviceFromFile.makeNew(imageFilename, blockSize * numBlocks)
    device.mount()
    try:
      currentTime = int(time())
      volumeId = uuid4().bytes
      
      # write superblocks and BGDTs
      superblock = _Superblock.new(1024, device, 0, blockSize, numBlocks, currentTime, volumeId)
      bgdt = _BGDT.new(0, superblock, device)
      
      if len(superblock.copyLocations) > 0:
        for bgNum in superblock.copyLocations[1:]:
          offset = (bgNum * superblock.numBlocksPerGroup + superblock.firstDataBlockId) * blockSize
          shadowSb = _Superblock.new(offset, device, bgNum, blockSize, numBlocks, currentTime, volumeId)
          _BGDT.new(bgNum, shadowSb, device)


      # write root directory
      rootInodeOffset = bgdt.entries[0].inodeTableLocation * superblock.blockSize + superblock.inodeSize
      zeroFill = [0] * (superblock.inodeSize - 26)
      fillFmt = ["B"] * (superblock.inodeSize - 26)
      uid = 0
      gid = 0
      mode = 0
      mode |= 0x4000 # set directory
      mode |= 0x0100 # user read
      mode |= 0x0080 # user write
      mode |= 0x0040 # user execute
      mode |= 0x0020 # group read
      mode |= 0x0008 # group execute
      mode |= 0x0004 # others read
      mode |= 0x0001 # others execute
      rootInodeBytes = pack("<2HI4IH", mode, uid, 0, currentTime, currentTime, currentTime, 0, gid)
      rootInodeBytes = "{0}{1}".format(rootInodeBytes, "".join(map(pack, fillFmt, zeroFill)))
      device.write(rootInodeOffset, rootInodeBytes)
      
      superblock._saveCopies = True
      bgdt.entries[0].numInodesAsDirs += 1
      
      fs = cls(device)
      fs._superblock = superblock
      fs._bgdt = bgdt
      fs._isValid = True
      
      rootBid = fs._allocateBlock(True)
      defaultEntries = pack("<IHBB1s3xIHBB2s", 2, 12, 1, 2, ".", 2, blockSize - 12, 2, 2, "..")
      fs._writeToBlock(rootBid, 0, defaultEntries)
      
      rootInode = fs._readInode(2)
      rootInode.numLinks += 2
      rootInode.assignNextBlockId(rootBid)
      rootInode.size += blockSize


      # write lost and found directory
      lfDir = fs.rootDir.makeDirectory("lost+found")
      while lfDir._inode.numDataBlocks < 8:
        newBid = fs._allocateBlock(True)
        lfDir._inode.assignNextBlockId(newBid)
        fs._writeToBlock(newBid, 4, pack("<H", blockSize))
        lfDir._inode.size += blockSize

      device.unmount()
      
    except Exception:
      if device.isMounted:
        device.unmount()
      if path.exists(imageFilename):
        remove(imageFilename)
      raise

    return cls(device)
    
  
  
  
  
  @classmethod
  def fromImageFile(cls, imageFilename):
    """Creates a new Ext2 filesystem from the specified image file."""
    return cls(_DeviceFromFile(imageFilename))
  
  def __init__(self, device):
    """Constructs a new Ext2 filesystem from the specified device object."""
    self._device = device
    self._isValid = False
  
  def __del__(self):
    """Destructor that unmounts the filesystem if it has not been unmounted."""
    if self._device.isMounted:
      self.unmount()
  
  def __enter__ (self):
    """Mounts the filesystem and returns the root directory."""
    self.mount()
    return self.rootDir

  def __exit__ (self, t, value, tb):
    """Unmounts the filesystem and re-raises any exception that occurred."""
    self.unmount()
  
  
  
  def mount(self):
    """Mounts the Ext2 filesystem for reading and writing and reads the root directory. Raises an
    error if the root directory cannot be read."""
    self._device.mount()
    try:
      self._superblock = _Superblock.read(1024, self._device)
      self._bgdt = _BGDT.read(0, self._superblock, self._device)
      self._isValid = True
      _openRootDirectory(self)
    except:
      if self._device.isMounted:
        self._device.unmount()
      self._isValid = False
      #raise FilesystemError("Root directory could not be read.")
      raise
  
  
  
  def unmount(self):
    """Unmounts the Ext2 filesystem so that reading and writing may no longer occur, and closes
    access to the device."""
    if self._device.isMounted:
      self._device.unmount()
    self._isValid = False
  
  
  
  
  def scanBlockGroups(self):
    """Scans all block groups and returns an information report about them."""
    assert self.isValid, "Filesystem is not valid."
    
    report = InformationReport()

    report.spaceUsed = 0
    
    # count files and directories
    report.numRegFiles = 0
    report.numSymlinks = 0
    report.numDirs = 1 # initialize with root directory
    q = deque([])
    q.append(self.rootDir)
    while len(q) > 0:
      d = q.popleft()
      for f in d.files():
        if f.name == "." or f.name == "..":
          continue
        for b in f._inode.usedBlocks():
          report.spaceUsed += self._superblock.blockSize
        if f.isDir:
          report.numDirs += 1
          q.append(f)
        elif f.isRegular:
          report.numRegFiles += 1
        elif f.isSymlink:
          report.numSymlinks += 1
    
    # report block group information
    report.groupReports = []
    for i,entry in enumerate(self._bgdt.entries):
      groupReport = InformationReport()
      groupReport.numFreeBlocks = entry.numFreeBlocks
      groupReport.numFreeInodes = entry.numFreeInodes
      groupReport.inodeBitmapLocation = entry.inodeBitmapLocation
      groupReport.blockBitmapLocation = entry.blockBitmapLocation
      groupReport.inodeTableLocation = entry.inodeTableLocation
      groupReport.numInodesAsDirs = entry.numInodesAsDirs
      report.groupReports.append(groupReport)
    
    return report
  
  
  
  
  def checkIntegrity(self):
    """Evaluates the integrity of the filesystem and returns an information report."""
    assert self.isValid, "Filesystem is not valid."
    
    report = InformationReport()
    checkPassed = True
    
    # basic integrity checks
    report.hasMagicNumber = self._superblock.isValidExt2
    report.numSuperblockCopies = len(self._superblock.copyLocations)
    report.copyLocations = list(self._superblock.copyLocations)
    report.messages = []
    
    
    # check consistency across superblock/group table copies by comparing all copies to first shadow copy
    if(len(self._superblock.copyLocations) > 1):
      sbCopiesGood = True
      bgdtCopiesGood = True
      
      firstSbCopyStartPos = (self._superblock.copyLocations[1] * self._superblock.numBlocksPerGroup
                             + self._superblock.firstDataBlockId) * self._superblock.blockSize
      firstSbCopy = _Superblock.read(firstSbCopyStartPos, self._device)

      firstBgtCopy = _BGDT.read(self._superblock.copyLocations[1], firstSbCopy, self._device)

      sbMembers = dict(inspect.getmembers(firstSbCopy))
      bgtMembersEntries = map(dict, map(inspect.getmembers, firstBgtCopy.entries))
      
      for groupId in self._superblock.copyLocations:
        if groupId == 0:
          continue
        
        # evaluate superblock copy consistency
        try:
          startPos = (groupId * self._superblock.numBlocksPerGroup + self._superblock.firstDataBlockId) * self._superblock.blockSize
          sbCopy = _Superblock.read(startPos, self._device)
          sbCopyMembers = dict(inspect.getmembers(sbCopy))
        except:
          report.messages.append("Superblock at block group {0} could not be read.".format(groupId))
          sbCopiesGood = False
          continue
        for m in sbMembers:
          if m.startswith("_"):
            continue
          if not m in sbCopyMembers:
            report.messages.append("Superblock at block group {0} has missing field '{1}'.".format(groupId, m))
            sbCopiesGood = False
          elif not sbCopyMembers[m] == sbMembers[m]:
            report.messages.append("Superblock at block group {0} has inconsistent field '{1}' with value '{2}' (first shadow copy has value '{3}').".format(groupId, m, sbCopyMembers[m], sbMembers[m]))
            sbCopiesGood = False
        
        # evaluate block group descriptor table consistency
        try:
          bgtCopy = _BGDT.read(groupId, self._superblock, self._device)
          bgtCopyMembersEntries = map(dict, map(inspect.getmembers, bgtCopy.entries))
        except:
          report.messages.append("Block group descriptor table at block group {0} could not be read.".format(groupId))
          bgdtCopiesGood = False
          continue
        if len(bgtCopyMembersEntries) != len(bgtMembersEntries):
          report.messages.append("Block group descriptor table at block group {0} has {1} entries while first shadow copy has {2}.".format(groupId, len(bgtCopyMembersEntries), len(bgtMembersEntries)))
          bgdtCopiesGood = False
          continue
        for entryNum in range(len(bgtMembersEntries)):
          bgtPrimaryEntryMembers = bgtMembersEntries[entryNum]
          bgtCopyEntryMembers = bgtCopyMembersEntries[entryNum]
          for m in bgtPrimaryEntryMembers:
            if m.startswith("_"):
              continue
            if not m in bgtCopyEntryMembers:
              report.messages.append("Block group descriptor table entry {0} at block group {1} has missing field '{2}'.".format(entryNum, groupId, m))
              bgdtCopiesGood = False
            elif not bgtCopyEntryMembers[m] == bgtPrimaryEntryMembers[m]:
              report.messages.append("Block group descriptor table entry {0} at block group {1} has inconsistent field '{2}' with value '{3}' (first shadow copy has value '{4}').".format(entryNum, groupId, m, bgtCopyEntryMembers[m], bgtPrimaryEntryMembers[m]))
              bgdtCopiesGood = False
      
      if sbCopiesGood:
        report.messages.append("Shadow superblock copies are all consistent.")
      if bgdtCopiesGood:
        report.messages.append("Shadow BGDT entries are all consistent.")

      checkPassed = sbCopiesGood and bgdtCopiesGood
    
    
    
    # validate inode and block references
    blocksGood = True
    inodesGood = True
    inodes = self.__getUsedInodes()
    inodesReachable = dict(zip(inodes, [False] * len(inodes)))
    blocks = self.__getUsedBlocks()
    blocksAccessedBy = dict(zip(blocks, [None] * len(blocks)))
    
    q = deque([])
    q.append(self.rootDir)
    while len(q) > 0:
      d = q.popleft()
      for f in d.files():
        if f.name == "." or f.name == "..":
          continue
        if f.isDir:
          q.append(f)
        
        # check inode references
        if not (f.isValid and f.inodeNum in inodesReachable):
          report.messages.append("The filesystem contains an entry for {0} but its inode is not marked as used (inode number {1}).".format(f.absolutePath, f.inodeNum))
          inodesGood = False
        else:
          inodesReachable[f.inodeNum] = True
        
        # check block references
        if not f.isSymlink or f.size > 60:
          for bid in f._inode.usedBlocks():
            if not bid in blocksAccessedBy:
              report.messages.append("The file {0} is referencing a block that is not marked as used by the filesystem (block id: {1})".format(f.absolutePath, bid))
              blocksGood = False
            elif blocksAccessedBy[bid]:
              report.messages.append("Block id {0} is being referenced by both {1} and {2}.".format(bid, blocksAccessedBy[bid], f.absolutePath))
              blocksGood = False
            else:
              blocksAccessedBy[bid] = f.absolutePath
    
    
    for inodeNum in inodesReachable:
      if not inodesReachable[inodeNum]:
        report.messages.append("Inode number {0} is marked as used but is not reachable from a directory entry.".format(inodeNum))
        inodesGood = False

    if blocksGood:
      report.messages.append("Block references look good.")
      
    if inodesGood:
      report.messages.append("Inode references look good.")
    
    checkPassed = checkPassed and blocksGood and inodesGood


    # validate group summary information for primary bgdt
    summaryGood = True
    totalFreeBlocks = 0
    totalFreeInodes = 0
    
    for entryNum,entry in enumerate(self._bgdt.entries):
      blockBitmap = unpack("{0}B".format(self._superblock.blockSize), self._readBlock(entry.blockBitmapLocation))
      inodeBitmap = unpack("{0}B".format(self._superblock.blockSize), self._readBlock(entry.inodeBitmapLocation))
      usedBlockCount = 0
      usedInodeCount = 0
      dirCount = 0
      index = 0
      
      maxBlocks = self._superblock.numBlocksPerGroup
      maxInodes = self._superblock.numInodesPerGroup
      if entryNum == self._superblock.numBlockGroups - 1:
        maxBlocks = self._superblock.numBlocks - ((self._superblock.numBlockGroups - 1) * self._superblock.numBlocksPerGroup) - self._superblock.firstDataBlockId
        maxInodes = self._superblock.numInodes - ((self._superblock.numBlockGroups - 1) * self._superblock.numInodesPerGroup)
        
      for i in range(self.blockSize):
        for j in range(8):
          if index < maxBlocks and (1 << j) & blockBitmap[i] != 0:
            usedBlockCount += 1
          if index < maxInodes and (1 << j) & inodeBitmap[i] != 0:
            usedInodeCount += 1
            inodeNum = (entryNum * self._superblock.numInodesPerGroup) + (i * 8) + j + 1
            inode = self._readInode(inodeNum)
            if (inode.mode & 0x4000) == 0x4000:
              dirCount += 1
          index += 1


      if dirCount != entry.numInodesAsDirs:
        summaryGood = False
        report.messages.append("Group {0} has wrong directories count. Read {1} but counted {2}.".format(entryNum, entry.numInodesAsDirs, dirCount))

      if maxBlocks - usedBlockCount != entry.numFreeBlocks:
        summaryGood = False
        report.messages.append("Group {0} has wrong free block count. Read {1} but counted {2}.".format(entryNum, entry.numFreeBlocks, maxBlocks - usedBlockCount))

      if maxInodes - usedInodeCount != entry.numFreeInodes:
        summaryGood = False
        report.messages.append("Group {0} has wrong free inode count. Read {1} but counted {2}.".format(entryNum, entry.numFreeInodes, maxInodes - usedInodeCount))

      totalFreeBlocks += (maxBlocks - usedBlockCount)
      totalFreeInodes += (maxInodes - usedInodeCount)

    if totalFreeBlocks != self._superblock.numFreeBlocks:
      summaryGood = False
      report.messages.append("Wrong free block count. Read {0} but counted {1}.".format(self._superblock.numFreeBlocks, totalFreeBlocks))

    if totalFreeInodes != self._superblock.numFreeInodes:
      summaryGood = False
      report.messages.append("Wrong free inode count. Read {0} but counted {1}.".format(self._superblock.numFreeInodes, totalFreeInodes))

    
    
    if summaryGood:
      report.messages.append("Group summary information looks good.")

    checkPassed = checkPassed and summaryGood



    if checkPassed:
      report.messages.append("[SUCCESS] Integrity check passed.")
    
    return report
  
  
  
  def __getUsedInodes(self):
    """Returns a list of all used inode numbers, excluding those reserved by the
    filesystem."""
    used = []
    bitmaps = []
    for bgdtEntry in self._bgdt.entries:
      bitmapStartPos = bgdtEntry.inodeBitmapLocation * self._superblock.blockSize
      bitmapSize = self._superblock.numInodesPerGroup / 8
      bitmapBytes = self._device.read(bitmapStartPos, bitmapSize)
      if len(bitmapBytes) < bitmapSize:
        raise FilesystemError("Invalid inode bitmap.")
      bitmaps.append(unpack("{0}B".format(bitmapSize), bitmapBytes))
    
    for groupNum,bitmap in enumerate(bitmaps):
      for byteIndex, byte in enumerate(bitmap):
        if byte != 0:
          for i in range(8):
            if (1 << i) & byte != 0:
              inum = (groupNum * self._superblock.numInodesPerGroup) + (byteIndex * 8) + i + 1
              if inum >= self._superblock.firstInode:
                used.append(inum)
    
    return used
  
  
  
  def __getUsedBlocks(self):
    """Returns a list off all block ids currently in use by the filesystem."""
    used = []
    bitmaps = []
    for bgdtEntry in self._bgdt.entries:
      bitmapStartPos = bgdtEntry.blockBitmapLocation * self._superblock.blockSize
      bitmapSize = self._superblock.numBlocksPerGroup / 8
      bitmapBytes = self._device.read(bitmapStartPos, bitmapSize)
      if len(bitmapBytes) < bitmapSize:
        raise FilesystemError("Invalid block bitmap.")
      bitmaps.append(unpack("{0}B".format(bitmapSize), bitmapBytes))
        
    for groupNum,bitmap in enumerate(bitmaps):
      for byteIndex, byte in enumerate(bitmap):
        if byte != 0:
          for i in range(8):
            if (1 << i) & byte != 0:
              bid = (groupNum * self._superblock.numBlocksPerGroup) + (byteIndex * 8) + i + self._superblock.firstDataBlockId
              used.append(bid)
    
    return used
    
  
  
  
  def _readBlock(self, bid, offset = 0, count = None):
    """Reads from the block specified by the given block id and returns a string of bytes."""
    if not count:
      count = self._superblock.blockSize
    block = self._device.read(bid * self._superblock.blockSize + offset, count)
    if len(block) < count:
      raise FilesystemError("Invalid block.")
    return block



  def _freeBlock(self, bid):
    """Frees the block specified by the given block id."""
    groupNum = (bid - self._superblock.firstDataBlockId) / self._superblock.numBlocksPerGroup
    indexInGroup = (bid - self._superblock.firstDataBlockId) % self._superblock.numBlocksPerGroup
    byteIndex = indexInGroup / 8
    bitIndex = indexInGroup % 8

    bgdtEntry = self._bgdt.entries[groupNum]
    bitmapStartPos = bgdtEntry.blockBitmapLocation * self._superblock.blockSize
    byte = unpack("B", self._device.read(bitmapStartPos + byteIndex, 1))[0]
    self._device.write(bitmapStartPos + byteIndex, pack("B", int(byte) & ~(1 << bitIndex)))
    self._superblock.numFreeBlocks += 1
    bgdtEntry.numFreeBlocks += 1



  def _allocateBlock(self, zeros = False):
    """Allocates the first free block and returns its id."""
    bitmapSize = self._superblock.numBlocksPerGroup / 8
    bitmapStartPos = None
    bgdtEntry = None
    groupNum = 0
    
    for groupNum, bgdtEntry in enumerate(self._bgdt.entries):
      if bgdtEntry.numFreeBlocks > 0:
        bitmapStartPos = bgdtEntry.blockBitmapLocation * self._superblock.blockSize
        break
    if bitmapStartPos is None:
      raise FilesystemError("No free blocks.")

    bitmapBytes = self._device.read(bitmapStartPos, bitmapSize)
    if len(bitmapBytes) < bitmapSize:
      raise FilesystemError("Invalid block bitmap.")
    bitmap = unpack("<{0}B".format(bitmapSize), bitmapBytes)

    for byteIndex, byte in enumerate(bitmap):
      if byte != 255:
        for i in range(8):
          if (1 << i) & byte == 0:
            bid = (groupNum * self._superblock.numBlocksPerGroup) + (byteIndex * 8) + i + self._superblock.firstDataBlockId
            self._device.write(bitmapStartPos + byteIndex, pack("B", byte | (1 << i)))
            self._superblock.numFreeBlocks -= 1
            bgdtEntry.numFreeBlocks -= 1
            if zeros:
              start = bid * self._superblock.blockSize
              zeros = [0] * self._superblock.blockSize
              fmt = ["B"] * self._superblock.blockSize
              self._device.write(start, "".join(map(pack, fmt, zeros)))
            self._superblock.timeLastWrite = int(time())
            return bid
    
    raise FilesystemError("No free blocks.")
  
  
  
  def _writeToBlock(self, bid, offset, byteString):
    """Writes the specified byte string to the specified block id at the given offset within the block."""
    assert offset + len(byteString) <= self._superblock.blockSize, "Byte array does not fit within block."
    self._device.write(offset + bid * self._superblock.blockSize, byteString)
    self._superblock.timeLastWrite = int(time())
    
  
  
  def _readInode(self, inodeNum):
    """Reads the specified inode number and returns the inode object."""
    return _Inode.read(inodeNum, self._bgdt, self._superblock, self)
  
  
  
  def _allocateInode(self, mode, uid, gid, creationTime, modTime, accessTime):
    """Allocates a new inode and returns the inode object."""
    return _Inode.new(self._bgdt, self._superblock, self, mode, uid, gid, creationTime, modTime, accessTime)




