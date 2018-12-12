#!/usr/bin/env python
"""
Defines the internal superblock class used by the ext2 module.
"""
__license__ = "BSD"
__copyright__ = "Copyright 2013, Michael R. Falcone"


from struct import pack,unpack_from
from math import ceil
from ..error import FilesystemError


class _Superblock(object):
  """Provides access to the filesystem's superblock. For internal use only."""
  _saveCopies = False


  @property
  def numInodes(self):
    """Gets the total number of inodes."""
    return self._numInodes

  @property
  def numBlocks(self):
    """Gets the total number of blocks."""
    return self._numBlocks

  @property
  def numReservedBlocks(self):
    """Gets the number of system reserved blocks."""
    return self._numResBlocks

  @property
  def firstDataBlockId(self):
    """Gets the id of the first block of the filesystem."""
    return self._firstBlockId

  @property
  def blockSize(self):
    """Gets the size of the filesystem blocks in bytes."""
    return self._blockSize

  @property
  def fragmentSize(self):
    """Gets the size of the fragments in bytes."""
    return self._fragSize

  @property
  def numBlocksPerGroup(self):
    """Gets the number of blocks per block group."""
    return self._numBlocksPerGroup

  @property
  def numFragmentsPerGroup(self):
    """Gets the number of fragments per block group."""
    return self._numFragsPerGroup

  @property
  def numInodesPerGroup(self):
    """Gets the number of inodes per block group."""
    return self._numInodesPerGroup

  @property
  def numMountsMax(self):
    """Gets the maximum number of times the filesystem should be mounted before being checked."""
    return self._numMountsMax

  @property
  def magicNumber(self):
    """Gets the value of the magic number field."""
    return self._magicNum

  @property
  def isValidExt2(self):
    """Gets whether the filesystem is Ext2 (if the magic number is 0xEF53)."""
    return (self._magicNum == 0xEF53)

  @property
  def errorAction(self):
    """Gets the action to take upon error."""
    return self._errorAction

  @property
  def revisionMinor(self):
    """Gets the minor revision level."""
    return self._revMinor

  @property
  def timeLastChecked(self):
    """Gets the time the filesystem was last checked."""
    return self._timeLastCheck

  @property
  def checkInterval(self):
    """Gets the maximum time that can pass before the filesystem should be checked, in ms."""
    return self._timeBetweenCheck

  @property
  def creatorOS(self):
    """Gets the name of the OS that created this filesystem."""
    return self._creatorOs

  @property
  def revisionMajor(self):
    """Gets the major revision level."""
    return self._revLevel

  @property
  def defaultReservedUID(self):
    """Gets the default UID allowed to use reserved blocks."""
    return self._defResUid

  @property
  def defaultReservedGID(self):
    """Gets the default GID allowed to use reserved blocks."""
    return self._defResGid

  @property
  def numBlockGroups(self):
    """Gets the number of block groups."""
    return self._numBlockGroups

  @property
  def copyLocations(self):
    """Gets a list of block group ids where a superblock copy is stored."""
    return self._copyBlockGroupIds

  @property
  def firstInode(self):
    """Gets the first inode index that can be used by user data."""
    return self._firstInodeIndex

  @property
  def inodeSize(self):
    """Gets the size of the inode structure in bytes."""
    return self._inodeSize

  @property
  def _groupNum(self):
    """Gets the group number of this superblock. This value is unique for each superblock copy."""
    return self.__groupNum

  @property
  def featuresCompatible(self):
    """Gets the bitmap of compatible features."""
    return self._featuresCompatible

  @property
  def featuresIncompatible(self):
    """Gets the bitmap of incompatible features (do not mount if an indicated feature is not supported)."""
    return self._featuresIncompatible

  @property
  def featuresReadOnlyCompatible(self):
    """Gets the bitmap of features that are read-only compatible."""
    return self._featuresReadOnlyCompatible

  @property
  def volumeId(self):
    """Gets the volume id."""
    return self._volumeId

  @property
  def lastMountPath(self):
    """Gets the path where the filesystem was last mounted."""
    return self._lastMountPath

  @property
  def compressionAlgorithms(self):
    """Gets the bitmap of compression algorithms used."""
    return self._compAlgorithms

  @property
  def numPreallocateBlocksFile(self):
    """Gets the number of blocks to preallocate for new files."""
    return self._numPreallocateBlocksFile

  @property
  def numPreallocateBlocksDir(self):
    """Gets the number of blocks to preallocate for new directories."""
    return self._numPreallocateBlocksDir

  @property
  def journalSuperblockUUID(self):
    """Gets the UUID of the journal superblock."""
    return self._journalSuperblockUuid

  @property
  def journalFileInode(self):
    """Gets the inode number of the journal file."""
    return self._journalFileInodeNum

  @property
  def journalFileDevice(self):
    """Gets the device number of the journal file."""
    return self._journalFileDev

  @property
  def lastOrphanInode(self):
    """Gets the inode number of the last orphan."""
    return self._lastOrphanInodeNum

  @property
  def hashSeeds(self):
    """Gets a list of 4 hash seeds used for directory indexing."""
    return self._hashSeeds

  @property
  def defaultHashVersion(self):
    """Gets the default hash version used for directory indexing."""
    return self._defHashVersion

  @property
  def defaultMountOptions(self):
    """Gets the default mount options."""
    return self._defMountOptions

  @property
  def firstMetaBlockGroup(self):
    """Gets the id of the first meta block group."""
    return self._firstMetaGroupId

  @property
  def logBlockSize(self):
    """Gets the log block size used by the filesystem."""
    return self._logBlockSize



  @property
  def numFreeBlocks(self):
    """Gets the number of free blocks."""
    return self._numFreeBlocks
  @numFreeBlocks.setter
  def numFreeBlocks(self, value):
    """Sets the number of free blocks."""
    self._numFreeBlocks = value
    self.__writeData(12, pack("<I", self._numFreeBlocks))

  @property
  def numFreeInodes(self):
    """Gets the number of free inodes."""
    return self._numFreeInodes
  @numFreeInodes.setter
  def numFreeInodes(self, value):
    """Sets the number of free inodes."""
    self._numFreeInodes = value
    self.__writeData(16, pack("<I", self._numFreeInodes))

  @property
  def timeLastMount(self):
    """Gets the last mount time."""
    return self._timeLastMount
  @timeLastMount.setter
  def timeLastMount(self, value):
    """Sets the last mount time."""
    self._timeLastMount = value
    self.__writeData(44, pack("<I", self._timeLastMount))

  @property
  def timeLastWrite(self):
    """Gets the time of last write access."""
    return self._timeLastWrite
  @timeLastWrite.setter
  def timeLastWrite(self, value):
    """Sets the time of last write access."""
    self._timeLastWrite = value
    self.__writeData(48, pack("<I", self._timeLastWrite))

  @property
  def numMountsSinceCheck(self):
    """Gets the number of mounts since the last filesystem check."""
    return self._numMountsSinceCheck
  @numMountsSinceCheck.setter
  def numMountsSinceCheck(self, value):
    """Sets the number of mounts since the last filesystem check."""
    self._numMountsSinceCheck = value
    self.__writeData(52, pack("<H", self._numMountsSinceCheck))

  @property
  def state(self):
    """Gets the state of the filesystem as a string that is either VALID or ERROR."""
    if self._state == 1:
      return "VALID"
    return "ERROR"
  @state.setter
  def state(self, value):
    """Sets the state of the filesystem as 1 for VALID or 0 for ERROR."""
    float(value) # raise exception if not a number
    self._state = value
    self.__writeData(58, pack("<H", self._state))

  @property
  def volumeName(self):
    """Gets the name of the volume."""
    return self._volName
  @volumeName.setter
  def volumeName(self, value):
    """Sets the name of the volume."""
    if len(value) > 15:
      raise FilesystemError("Volume name too long.")
    self._volName = value
    self.__writeData(120, pack("<{0}sB".format(len(self._volName)), self._volName, 0))




  @classmethod
  def new(cls, byteOffset, device, bgNum, blockSize, numBlocks, currentTime, volumeId):
    """Creates a new superblock at the byte offset in the specified image file, and returns
    the new superblock object."""

    firstInodeIndex = 11
    inodeSize = 128
    numInodesPerGroup = blockSize * 8
    numResBlocks = int(numBlocks * 0.05)
    numBlocksPerGroup = blockSize * 8
    numBlockGroups = int(ceil(float(numBlocks) / numBlocksPerGroup))

    if blockSize > 1024:
      firstBlockId = 0
    else:
      firstBlockId = 1
    
    copyBlockGroupIds = []
    if numBlockGroups > 1:
      copyBlockGroupIds.append(1)
      last3 = 3
      while last3 < numBlockGroups:
        copyBlockGroupIds.append(last3)
        last3 *= 3
      last5 = 5
      while last5 < numBlockGroups:
        copyBlockGroupIds.append(last5)
        last5 *= 5
      last7 = 7
      while last7 < numBlockGroups:
        copyBlockGroupIds.append(last7)
        last7 *= 7

    bgdtBlocks = int(ceil(float(numBlockGroups * 32) / blockSize))
    inodeTableBlocks = int(ceil(float(numInodesPerGroup * inodeSize) / blockSize))
    numFreeBlocks = (numBlocks - firstBlockId - inodeTableBlocks * numBlockGroups - 2 * numBlockGroups -
                    (1 + bgdtBlocks) * (len(copyBlockGroupIds) + 1))
    
    # if the final block group doesn't have enough space for bookkeeping blocks, remove it
    lastBgId = numBlockGroups - 1
    overhead = 2 + inodeTableBlocks
    if lastBgId in copyBlockGroupIds:
      overhead += (1 + bgdtBlocks)
    if overhead > numBlocks - (lastBgId * numBlocksPerGroup + firstBlockId):
      if lastBgId in copyBlockGroupIds:
        copyBlockGroupIds.remove(lastBgId)
      numBlockGroups -= 1
      numBlocks = numBlockGroups * numBlocksPerGroup
      bgdtBlocks = int(ceil(float(numBlockGroups * 32) / blockSize))
      numFreeBlocks = (numBlocks - firstBlockId - inodeTableBlocks * numBlockGroups - 2 * numBlockGroups -
                      (1 + bgdtBlocks) * (len(copyBlockGroupIds) + 1))
    
    if numFreeBlocks < 10:
      raise FilesystemError("Not enough blocks specified.")

    numInodes = numInodesPerGroup * numBlockGroups
    numFreeInodes = numInodes - (firstInodeIndex - 1)
    
    logBlockSize = blockSize >> 11
    logFragSize = blockSize >> 11
    numFragsPerGroup = numBlocksPerGroup
    if numBlocks < numBlocksPerGroup:
      numBlocksPerGroup = numBlocks
      numFragsPerGroup = numBlocks
    timeLastMount = currentTime
    timeLastWrite = currentTime
    numMountsSinceCheck = 0
    numMountsMax = 25
    magicNum = 0xEF53
    state = 1
    errorAction = 1
    revMinor = 0
    timeLastCheck = currentTime
    timeBetweenCheck = 15552000
    creatorOs = 0
    revLevel = 1
    defResUid = 0
    defResGid = 0
    featuresCompatible = 0
    featuresIncompatible = 2
    featuresReadOnlyCompatible = 1
    volName = "{0}".format(pack("B", 0))
    lastMountPath = "/{0}".format(pack("B", 0))
    
    sbBytes = pack("<7Ii5I6H4I2HI2H3I16s16s64s", numInodes, numBlocks, numResBlocks, numFreeBlocks, numFreeInodes,
                   firstBlockId, logBlockSize, logFragSize, numBlocksPerGroup, numFragsPerGroup,
                   numInodesPerGroup, timeLastMount, timeLastWrite, numMountsSinceCheck, numMountsMax,
                   magicNum, state, errorAction, revMinor, timeLastCheck, timeBetweenCheck, creatorOs,
                   revLevel, defResUid, defResGid, firstInodeIndex, inodeSize, bgNum, featuresCompatible,
                   featuresIncompatible, featuresReadOnlyCompatible, volumeId, volName, lastMountPath)
    zeroFill = [0] * 824
    fillFmt = ["B"] * 824
    sbBytes = "{0}{1}".format(sbBytes, "".join(map(pack, fillFmt, zeroFill)))
    
    device.write(byteOffset, sbBytes)

    return cls(sbBytes, byteOffset, device)


  @classmethod
  def read(cls, byteOffset, device):
    """Reads a superblock from the bytes at byteOffset in device and returns the superblock object."""
    sbBytes = device.read(byteOffset, 1024)
    if len(sbBytes) < 1024:
      raise FilesystemError("Invalid superblock.")
    return cls(sbBytes, byteOffset, device)


  def __init__(self, sbBytes, byteOffset, device):
    """Constructs a new superblock from the given byte array."""
    self._byteOffset = byteOffset
    self._device = device

    # read standard fields
    fields = unpack_from("<7Ii5I6H4I2H", sbBytes)
    self._numInodes = fields[0]
    self._numBlocks = fields[1]
    self._numResBlocks = fields[2]
    self._numFreeBlocks = fields[3]
    self._numFreeInodes = fields[4]
    self._firstBlockId = fields[5]
    self._blockSize = 1024 << fields[6]
    self._logBlockSize = fields[6]
    if fields[7] > 0:
      self._fragSize = 1024 << fields[7]
    else:
      self._fragSize = 1024 >> abs(fields[7])
    self._numBlocksPerGroup = fields[8]
    self._numFragsPerGroup = fields[9]
    self._numInodesPerGroup = fields[10]
    self._timeLastMount = fields[11]
    self._timeLastWrite = fields[12]
    self._numMountsSinceCheck = fields[13]
    self._numMountsMax = fields[14]
    self._magicNum = fields[15]
    if fields[16] == 1:
      self._state = "VALID"
    else:
      self._state = "ERROR"
    if fields[17] == 1:
      self._errorAction = "CONTINUE"
    elif fields[17] == 2:
      self._errorAction = "RO"
    else:
      self._errorAction = "PANIC"
    self._revMinor = fields[18]
    self._timeLastCheck = fields[19]
    self._timeBetweenCheck = fields[20]
    if fields[21] == 0:
      self._creatorOs = "LINUX"
    elif fields[21] == 1:
      self._creatorOs = "HURD"
    elif fields[21] == 2:
      self._creatorOs = "MASIX"
    elif fields[21] == 3:
      self._creatorOs = "FREEBSD"
    elif fields[21] == 4:
      self._creatorOs = "LITES"
    else:
      self._creatorOs = "UNDEFINED"
    self._revLevel = fields[22]
    self._defResUid = fields[23]
    self._defResGid = fields[24]

    self._numBlockGroups = int(ceil(float(self._numBlocks) / self._numBlocksPerGroup))


    # read additional fields
    if self._revLevel == 0:
      self._firstInodeIndex = 11
      self._inodeSize = 128
      self.__groupNum = 0
      self._featuresCompatible = 0
      self._featuresIncompatible = 0
      self._featuresReadOnlyCompatible = 0
      self._volumeId = ""
      self._volName = ""
      self._lastMountPath = ""
      self._compAlgorithms = None
      self._numPreallocateBlocksFile = 0
      self._numPreallocateBlocksDir = 0
      self._journalSuperblockUuid = None
      self._journalFileInodeNum = None
      self._journalFileDev = None
      self._lastOrphanInodeNum = None
      self._hashSeeds = None
      self._defHashVersion = None
      self._defMountOptions = None
      self._firstMetaGroupId = None
      self._copyBlockGroupIds = range(self._numBlockGroups)

    else:
      fields = unpack_from("<I2H3I16s16s64sI2B2x16s3I4IB3x2I", sbBytes, 84)
      self._firstInodeIndex = fields[0]
      self._inodeSize = fields[1]
      self.__groupNum = fields[2]
      self._featuresCompatible = fields[3]
      self._featuresIncompatible = fields[4]
      self._featuresReadOnlyCompatible = fields[5]
      self._volumeId = fields[6].rstrip('\0')
      self._volName = fields[7].rstrip('\0')
      self._lastMountPath = fields[8].rstrip('\0')
      self._compAlgorithms = fields[9]
      self._numPreallocateBlocksFile = fields[10]
      self._numPreallocateBlocksDir = fields[11]
      self._journalSuperblockUuid = fields[12].rstrip('\0')
      self._journalFileInodeNum = fields[13]
      self._journalFileDev = fields[14]
      self._lastOrphanInodeNum = fields[15]
      self._hashSeeds = []
      self._hashSeeds.append(fields[16])
      self._hashSeeds.append(fields[17])
      self._hashSeeds.append(fields[18])
      self._hashSeeds.append(fields[19])
      self._defHashVersion = fields[20]
      self._defMountOptions = fields[21]
      self._firstMetaGroupId = fields[22]

      self._copyBlockGroupIds = []
      self._copyBlockGroupIds.append(0)
      if self._numBlockGroups > 1:
        self._copyBlockGroupIds.append(1)
        last3 = 3
        while last3 < self._numBlockGroups:
          self._copyBlockGroupIds.append(last3)
          last3 *= 3
        last5 = 5
        while last5 < self._numBlockGroups:
          self._copyBlockGroupIds.append(last5)
          last5 *= 5
        last7 = 7
        while last7 < self._numBlockGroups:
          self._copyBlockGroupIds.append(last7)
          last7 *= 7
        self._copyBlockGroupIds.sort()



  def __writeData(self, offset, byteString):
    """Writes the specified string of bytes at the specified offset (from the start of the superblock bytes)
    on the device."""
    for groupId in self.copyLocations:
      sbStart = 1024 + groupId * self.numBlocksPerGroup * self.blockSize
      
      self._device.write(sbStart + offset, byteString)
      if not self._saveCopies:
        break
