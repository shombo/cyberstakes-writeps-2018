#!/usr/bin/env python
"""
Defines classes for accessing the device on which the filesystem resides.
"""
__license__ = "BSD"
__copyright__ = "Copyright 2013, Michael R. Falcone"


from os import fsync, path, makedirs
from struct import pack
from ..error import FilesystemError


class _DeviceFromFile(object):
  """Represents a device from a filesystem image file."""
  
  @property
  def isMounted(self):
    """Returns whether the device is currently mounted."""
    return (not self._imageFile is None)

  @classmethod
  def makeNew(cls, imageFilename, numBytes):
    """Creates a new device image with the specified filename."""
    destDirectory = path.dirname(imageFilename)
    if len(destDirectory) > 0:
      if not path.exists(destDirectory):
        makedirs(destDirectory)
    
    if path.exists(imageFilename):
      raise FilesystemError("Specified image file already exists.")
    
    f = open(imageFilename, "wb")
    with f:
      f.seek(numBytes-1)
      f.write(pack("B", 0))
      
    return cls(imageFilename)
  
  def __init__(self, filename):
    """Constructs a new device object from the specified file."""
    self._imageFilename = filename
    self._imageFile = None
  
  def mount(self):
    """Opens reading/writing from/to the device."""
    self._imageFile = open(self._imageFilename, "r+b")
    self._imageFile.seek(0, 2)
    self._imageSize = self._imageFile.tell()
    self._imageFile.seek(0)

  def unmount(self):
    """Closes reading/writing from/to the device."""
    if self._imageFile:
      self._imageFile.flush()
      fsync(self._imageFile.fileno())
      self._imageFile.close()
    self._imageFile = None

  def read(self, position, size):
    """Reads a byte string of the specified size from the specified position."""
    assert self.isMounted, "Device not mounted."
    assert position+size <= self._imageSize, "Requested bytes out of range."
    self._imageFile.seek(position)
    return self._imageFile.read(size)
  
  def write(self, position, byteString):
    """Writes the specified byte string to the specified byte position."""
    assert self.isMounted, "Device not mounted."
    assert position+len(byteString) <= self._imageSize,\
      "Invalid device position [device size: {0} bytes].".format(self._imageSize)
    self._imageFile.seek(position)
    self._imageFile.write(byteString)
    self._imageFile.flush()
