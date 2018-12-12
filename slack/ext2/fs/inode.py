#!/usr/bin/env python
"""
Defines the internal inode class used by the ext2 module.
"""
__license__ = "BSD"
__copyright__ = "Copyright 2013, Michael R. Falcone"


from struct import pack, unpack, unpack_from
from time import time
from math import ceil
from ..error import FilesystemError


class _Inode(object):
  """Models an inode on the Ext2 fileystem. For internal use only."""


  @property
  def number(self):
    """Gets the inode number of this inode."""
    return self._num

  @property
  def isUsed(self):
    """Returns True if the inode is marked as used, False otherwise."""
    return self._used

  @property
  def timeCreated(self):
    """Gets the time this inode was created."""
    return self._timeCreated

  @property
  def flags(self):
    """Gets the flags bitmap for this inode."""
    return self._flags

  @property
  def blocks(self):
    """Gets the list of block ids used by the inode."""
    return self._blocks

  @property
  def numBlocks(self):
    """Gets the total number of blocks used by the inode."""
    return self._numDataBlocks
  
  @property
  def numDataBlocks(self):
    """Gets the number of blocks used for only data inside the inode."""
    return int(ceil(float(self._size) / self._superblock.blockSize))

  @property
  def mode(self):
    """Gets the mode bitmap."""
    return self._mode
  @mode.setter
  def mode(self, value):
    """Sets the mode bitmap."""
    self._mode = value
    self.__writeData(0, pack("<H", (self._mode & 0xFFFF)))
    if self._superblock.creatorOS == "HURD":
      self.__writeData(118, pack("<H", (self._mode >> 16)))

  @property
  def uid(self):
    """Gets the uid of the inode's owner."""
    return self._uid
  @uid.setter
  def uid(self, value):
    """Sets the uid of the inode's owner."""
    self._uid = value
    self.__writeData(2, pack("<H", (self._uid & 0xFFFF)))
    if self._superblock.creatorOS == "LINUX" or self._superblock.creatorOS == "HURD":
      self.__writeData(120, pack("<H", (self._uid >> 16)))

  @property
  def size(self):
    """Gets the size in bytes of the inode's file."""
    return self._size
  @size.setter
  def size(self, value):
    """Sets the size in bytes of the inode's file."""
    self._size = value
    self.__writeData(4, pack("<I", (self._size & 0xFFFFFFFF)))
    # if regular file on revision > 0, save upper 32 bits of size in dir ACL field
    if self._superblock.revisionMajor > 0 and (self._mode & 0x8000) != 0:
      self.__writeData(108, pack("<I", (self._size >> 32)))

  @property
  def timeAccessed(self):
    """Gets the time the inode was last accessed."""
    return self._timeAccessed
  @timeAccessed.setter
  def timeAccessed(self, value):
    """Sets the time the inode was last accessed."""
    self._timeAccessed = value
    self.__writeData(8, pack("<I", self._timeAccessed))

  @property
  def timeModified(self):
    """Gets the time the inode was last modified."""
    return self._timeModified
  @timeModified.setter
  def timeModified(self, value):
    """Sets the time the inode was last modified."""
    self._timeModified = value
    self.__writeData(16, pack("<I", self._timeModified))

  @property
  def timeDeleted(self):
    """Gets the time the inode was deleted."""
    return self._timeDeleted
  @timeDeleted.setter
  def timeDeleted(self, value):
    """Sets the time the inode was deleted."""
    self._timeDeleted = value
    self.__writeData(20, pack("<I", self._timeDeleted))

  @property
  def gid(self):
    """Gets the gid of the inode's owner."""
    return self._gid
  @gid.setter
  def gid(self, value):
    """Sets the gid of the inode's owner."""
    self._gid = value
    self.__writeData(24, pack("<H", (self._gid & 0xFFFF)))
    if self._superblock.creatorOS == "LINUX" or self._superblock.creatorOS == "HURD":
      self.__writeData(122, pack("<H", (self._gid >> 16)))

  @property
  def numLinks(self):
    """Gets the number of hard links to the inode."""
    return self._numLinks
  @numLinks.setter
  def numLinks(self, value):
    """Sets the number of hard links to the inode."""
    self._numLinks = value
    self.__writeData(26, pack("<h", self._numLinks))





  @classmethod
  def new(cls, bgdt, superblock, fs, mode, uid, gid, creationTime, modTime, accessTime):
    """Allocates the first free inode and returns the new inode object."""
    
    bgroupNum = 0
    bgdtEntry = None
    bitmapSize = superblock.numInodesPerGroup / 8

    for bgroupNum, bgdtEntry in enumerate(bgdt.entries):
      if bgdtEntry.numFreeInodes > 0:
        break
    if bgdtEntry is None:
      raise FilesystemError("No free inodes.")

    bitmapBytes = fs._readBlock(bgdtEntry.inodeBitmapLocation, 0, bitmapSize)
    if len(bitmapBytes) < bitmapSize:
      raise FilesystemError("Invalid inode bitmap.")

    
    def getAndMarkInode(bitmap):
      for byteIndex, byte in enumerate(bitmap):
        if byte != 255:
          for i in range(8):
            if (1 << i) & byte == 0:
              inodeNum = (bgroupNum * superblock.numInodesPerGroup) + (byteIndex * 8) + i + 1
              if inodeNum < superblock.firstInode:
                continue
              fs._writeToBlock(bgdtEntry.inodeBitmapLocation, byteIndex, pack("B", byte | (1 << i)))
              return inodeNum
      return None

    inodeNum = getAndMarkInode(unpack("{0}B".format(bitmapSize), bitmapBytes))
    if inodeNum is None:
      raise FilesystemError("No free inodes.")

    superblock.numFreeInodes -= 1
    bgdtEntry.numFreeInodes -= 1
    if (mode & 0x4000) != 0:
      bgdtEntry.numInodesAsDirs += 1


    if superblock.creatorOS == "LINUX":
      osdBytes = pack("<4x2H", (uid >> 16), (gid >> 16))
    elif superblock.creatorOS == "HURD":
      osdBytes = pack("<2x3H", (mode >> 16), (uid >> 16), (gid >> 16))
    else:
      osdBytes = pack("<12x")
    
    inodeBytes = pack("<2Hi4IH90x12s", (mode & 0xFFFF), (uid & 0xFFFF), 0, accessTime, creationTime, modTime, 0,
      (gid & 0xFFFF), osdBytes)
    
    # write new inode bytes to the device
    bgroupIndex = (inodeNum - 1) % superblock.numInodesPerGroup
    tableBid = bgdtEntry.inodeTableLocation + (bgroupIndex * superblock.inodeSize) / fs.blockSize
    inodeTableOffset = (bgroupIndex * superblock.inodeSize) % fs.blockSize
    fs._writeToBlock(tableBid, inodeTableOffset, inodeBytes)

    return cls(tableBid, inodeTableOffset, inodeBytes, True, inodeNum, bgdtEntry, superblock, fs)



  @classmethod
  def read(cls, inodeNum, bgdt, superblock, fs):
    """Reads the inode with the specified inode number and returns the new object."""

    bgroupNum = (inodeNum - 1) / superblock.numInodesPerGroup
    bgroupIndex = (inodeNum - 1) % superblock.numInodesPerGroup
    bgdtEntry = bgdt.entries[bgroupNum]

    bitmapByteIndex = bgroupIndex / 8
    tableBid = bgdtEntry.inodeTableLocation + (bgroupIndex * superblock.inodeSize) / fs.blockSize
    inodeTableOffset = (bgroupIndex * superblock.inodeSize) % fs.blockSize
    
    bitmapByte = unpack("B", fs._readBlock(bgdtEntry.inodeBitmapLocation, bitmapByteIndex, 1))[0]
    inodeBytes = fs._readBlock(tableBid, inodeTableOffset, superblock.inodeSize)
    if len(inodeBytes) < superblock.inodeSize:
      raise FilesystemError("Invalid inode.")

    isUsed = (bitmapByte & (1 << (bgroupIndex % 8)) != 0)
    return cls(tableBid, inodeTableOffset, inodeBytes, isUsed, inodeNum, bgdtEntry, superblock, fs)




  def __init__(self, tableBid, inodeTableOffset, inodeBytes, isUsed, inodeNum, bgdtEntry, superblock, fs):
    """Constructs a new inode from the given byte array."""
    self._bgdtEntry = bgdtEntry
    self._tableBid = tableBid
    self._fs = fs
    self._superblock = superblock
    self._inodeTableOffset = inodeTableOffset
    
    if superblock.revisionMajor == 0:
      fields = unpack_from("<2Hi4IHh2I4x15I", inodeBytes)
    else:
      fields = unpack_from("<2H5IHh2I4x15I8xI", inodeBytes)

    osFields = []
    if superblock.creatorOS == "LINUX":
      osFields = unpack_from("<4x2H", inodeBytes, 116)
    elif superblock.creatorOS == "HURD":
      osFields = unpack_from("<2x3H", inodeBytes, 116)
      
    self._num = inodeNum
    self._used = isUsed
    self._mode = fields[0]
    self._uid = fields[1]
    self._size = fields[2]
    self._timeAccessed = fields[3]
    self._timeCreated = fields[4]
    self._timeModified = fields[5]
    self._timeDeleted = fields[6]
    self._gid = fields[7]
    self._numLinks = fields[8]
    self._numDataBlocks = fields[9] / (2 << self._superblock.logBlockSize)
    self._flags = fields[10]
    self._blocks = []
    for i in range(15):
      self._blocks.append(fields[11+i])
    if superblock.revisionMajor > 0:
      self._size |= (fields[26] << 32)
    if superblock.creatorOS == "LINUX":
      self._uid |= (osFields[0] << 16)
      self._gid |= (osFields[1] << 16)
    elif superblock.creatorOS == "HURD":
      self._mode |= (osFields[0] << 16)
      self._uid |= (osFields[1] << 16)
      self._gid |= (osFields[2] << 16)

    self._numIdsPerBlock = self._superblock.blockSize / 4
    self._numDirectBlocks = 12
    self._numIndirectBlocks = self._numDirectBlocks + self._numIdsPerBlock
    self._numDoublyIndirectBlocks = self._numIndirectBlocks + self._numIdsPerBlock ** 2
    self._numTreblyIndirectBlocks = self._numDoublyIndirectBlocks + self._numIdsPerBlock ** 3


  def free(self):
    """Frees this inode so that it can be reused. All referenced blocks should be freed before calling."""
    indexInGroup = (self.number - 1) % self._superblock.numInodesPerGroup
    byteIndex = indexInGroup / 8
    bitIndex = indexInGroup % 8
    
    byte = unpack("B", self._fs._readBlock(self._bgdtEntry.inodeBitmapLocation, byteIndex, 1))[0]
    self._fs._writeToBlock(self._bgdtEntry.inodeBitmapLocation, byteIndex, pack("B", int(byte) & ~(1 << bitIndex)))
    self._superblock.numFreeInodes += 1
    self._bgdtEntry.numFreeInodes += 1
    if (self.mode & 0x4000) != 0:
      self._bgdtEntry.numInodesAsDirs -= 1
    self.timeDeleted = int(time())
    self._used = False
    


  def usedBlocks(self):
    """Generates a list of all block ids in use by the inode, including data
    and indirect blocks."""
    
    # get direct blocks
    for i in range(12):
      bid = self.blocks[i]
      if bid == 0:
        break
      yield bid

    # get indirect blocks
    if self.blocks[12] != 0:
      for bid in self.__getBidListAtBid(self.blocks[12]):
        if bid == 0:
          break
        yield bid
      yield self.blocks[12]

    # get doubly indirect blocks
    if self.blocks[13] != 0:
      for indirectBid in self.__getBidListAtBid(self.blocks[13]):
        if indirectBid == 0:
          break
        for bid in self.__getBidListAtBid(indirectBid):
          if bid == 0:
            break
          yield bid
        yield indirectBid
      yield self.blocks[13]

    # get trebly indirect blocks
    if self.blocks[14] != 0:
      for doublyIndirectBid in self.__getBidListAtBid(self.blocks[14]):
        if doublyIndirectBid == 0:
          break
        for indirectBid in self.__getBidListAtBid(doublyIndirectBid):
          if indirectBid == 0:
            break
          for bid in self.__getBidListAtBid(indirectBid):
            if bid == 0:
              break
            yield bid
          yield indirectBid
        yield doublyIndirectBid
      yield self.blocks[14]




  def lookupBlockId(self, index):
    """Looks up the block id corresponding to the block at the specified index,
    where the block index is the absolute block number within the data."""
    
    if index >= self._numDataBlocks:
      return 0
    
    try:
      if index < self._numDirectBlocks:
        return self.blocks[index]

      elif index < self._numIndirectBlocks:
        directList = self.__getBidListAtBid(self.blocks[12])
        return directList[index - self._numDirectBlocks]

      elif index < self._numDoublyIndirectBlocks:
        indirectList = self.__getBidListAtBid(self.blocks[13])
        index -= self._numIndirectBlocks # get index from start of doubly indirect list
        directList = self.__getBidListAtBid(indirectList[index / self._numIdsPerBlock])
        return directList[index % self._numIdsPerBlock]

      elif index < self._numTreblyIndirectBlocks:
        doublyIndirectList = self.__getBidListAtBid(self.blocks[14])
        index -= self._numDoublyIndirectBlocks # get index from start of trebly indirect list
        indirectList = self.__getBidListAtBid(doublyIndirectList[index / (self._numIdsPerBlock ** 2)])
        index %= (self._numIdsPerBlock ** 2) # get index from start of indirect list
        directList = self.__getBidListAtBid(indirectList[index / self._numIdsPerBlock])
        return directList[index % self._numIdsPerBlock]
      
      return 0
    except IndexError:
      return 0
  
  
  
  def assignStringToBlocks(self, path):
    """Assigns the specified string to the block data."""
    pathBytes = pack("<{0}s{1}x".format(len(path), 60 - len(path)), path)
    self.__writeData(40, pathBytes)
    self._blocks = list(unpack_from("<15I", pathBytes))


  def getStringFromBlocks(self):
    """Reads and returns block data as a string."""
    pathBytes = self._fs._readBlock(self._tableBid, self._inodeTableOffset + 40, self._size)
    return unpack_from("<{0}s".format(self._size), pathBytes)[0]


  def assignNextBlockId(self, bid):
    """Assigns the given block id to this inode as the next block in use. Returns the new number
    of blocks."""
    
    if self._numDataBlocks < self._numDirectBlocks:
      self._blocks[self._numDataBlocks] = bid
      self.__writeData(40+(self._numDataBlocks*4), pack("<I", bid))
      self._numDataBlocks += 1
      self.__writeData(28, pack("<I", self._numDataBlocks * (2 << self._superblock.logBlockSize)))
      return self._numDataBlocks
    

    elif self._numDataBlocks < self._numIndirectBlocks + 1:
      if self.blocks[12] == 0:
        self.blocks[12] = self._fs._allocateBlock(True)
        self._numDataBlocks += 1
        self.__writeData(88, pack("<I", self.blocks[12]))
      self.__writeToBidListAtBid(self.blocks[12], self._numDataBlocks - self._numDirectBlocks - 1, bid)
      self._numDataBlocks += 1
      self.__writeData(28, pack("<I", self._numDataBlocks * (2 << self._superblock.logBlockSize)))
      return self._numDataBlocks


    elif self._numDataBlocks < self._numDoublyIndirectBlocks + self._numIdsPerBlock + 2:
      if self.blocks[13] == 0:
        self.blocks[13] = self._fs._allocateBlock(True)
        self._numDataBlocks += 1
        self.__writeData(92, pack("<I", self.blocks[13]))
      indirectList = self.__getBidListAtBid(self.blocks[13])
      
      index = self._numDataBlocks - self._numIndirectBlocks - 2
      indirectIndex = index / (self._numIdsPerBlock + 1)
      directIndex = index % (self._numIdsPerBlock + 1) - 1
      
      if indirectList[indirectIndex] == 0:
        indirectList[indirectIndex] = self._fs._allocateBlock(True)
        self._numDataBlocks += 1
        self.__writeToBidListAtBid(self.blocks[13], indirectIndex, indirectList[indirectIndex])
        directIndex += 1
      directList = self.__getBidListAtBid(indirectList[indirectIndex])
      
      directList[directIndex] = bid
      self.__writeToBidListAtBid(indirectList[indirectIndex], directIndex, directList[directIndex])
      self._numDataBlocks += 1
      self.__writeData(28, pack("<I", self._numDataBlocks * (2 << self._superblock.logBlockSize)))
      return self._numDataBlocks


    else:
      index = self._numDataBlocks - self._numDoublyIndirectBlocks - self._numIdsPerBlock - 3
      if self.blocks[14] == 0:
        self.blocks[14] = self._fs._allocateBlock(True)
        self._numDataBlocks += 1
        self.__writeData(96, pack("<I", self.blocks[14]))
        index += 1
      doublyIndirectList = self.__getBidListAtBid(self.blocks[14])
      
      
      numDoublyIndirectBlocks = self._numIdsPerBlock ** 2 + self._numIdsPerBlock + 1
      doublyIndirectIndex = index / numDoublyIndirectBlocks
      
      
      if doublyIndirectList[doublyIndirectIndex] == 0:
        doublyIndirectList[doublyIndirectIndex] = self._fs._allocateBlock(True)
        self._numDataBlocks += 1
        self.__writeToBidListAtBid(self.blocks[14], doublyIndirectIndex, doublyIndirectList[doublyIndirectIndex])
        index += 1
      indirectList = self.__getBidListAtBid(doublyIndirectList[doublyIndirectIndex])
      
      indirectIndex = ((index - numDoublyIndirectBlocks - 1) % numDoublyIndirectBlocks) / (self._numIdsPerBlock + 1)
      
      if indirectList[indirectIndex] == 0:
        indirectList[indirectIndex] = self._fs._allocateBlock(True)
        self._numDataBlocks += 1
        self.__writeToBidListAtBid(doublyIndirectList[doublyIndirectIndex], indirectIndex, indirectList[indirectIndex])
        index += 1
      directList = self.__getBidListAtBid(indirectList[indirectIndex])

      overheadBlocks = (doublyIndirectIndex * self._numIdsPerBlock) + doublyIndirectIndex + indirectIndex + 2
      dataBlocks = doublyIndirectIndex * self._numIdsPerBlock ** 2
      directIndex = (index - overheadBlocks - dataBlocks) % self._numIdsPerBlock

      directList[directIndex] = bid
      self.__writeToBidListAtBid(indirectList[indirectIndex], directIndex, directList[directIndex])
      self._numDataBlocks += 1
      self.__writeData(28, pack("<I", self._numDataBlocks * (2 << self._superblock.logBlockSize)))
      return self._numDataBlocks




  def __getBidListAtBid(self, bid):
    """Reads and returns the list of block ids at the specified block id."""
    return list(unpack_from("<{0}I".format(self._numIdsPerBlock), self._fs._readBlock(bid)))


  def __writeToBidListAtBid(self, listBid, listIndex, bidToWrite):
    """Writes the specified block id to the list at the block id specified by listBid."""
    self._fs._writeToBlock(listBid, listIndex * 4, pack("<I", bidToWrite))
  
  
  def __writeData(self, offset, byteString):
    """Writes the specified string of bytes at the specified offset (from the start of the inode bytes)
    on the device."""
    self._fs._writeToBlock(self._tableBid, self._inodeTableOffset + offset, byteString)
