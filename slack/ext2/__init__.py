#!/usr/bin/env python
"""
Module for interfacing with an Ext2 filesystem image.
"""
__license__ = "BSD"
__copyright__ = "Copyright 2013, Michael R. Falcone"

from .error import *
from .fs import Ext2Filesystem
from .file import Ext2File
__all__ = ["Ext2File", "Ext2Filesystem", "FilesystemError", "InvalidFileTypeError",
           "UnsupportedOperationError", "FileNotFoundError"]
