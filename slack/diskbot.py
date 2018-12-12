#!/usr/bin/env python
"""
Driver application for interfacing with a filesystem image that can generate
information about the filesystem and enter an interactive shell.
"""
__license__ = "BSD"
__copyright__ = "Copyright 2013, Michael R. Falcone"

import sys
import os
from time import sleep, clock
from threading import Thread
from collections import deque
from ext2 import *


class FilesystemNotSupportedError(Exception):
  """Thrown when the image's filesystem type is not supported."""
  pass


class ShellError(Exception):
  """Thrown when the shell encounters an error."""
  pass


class WaitIndicatorThread(Thread):
  """Shows a wait indicator for the current action. If maxProgress is set then a
  percentage towards completion is shown instead."""
  done = False
  progress = 0
  maxProgress = 0

  def __init__(self, msg):
    Thread.__init__(self)
    self._msg = msg

  def run(self):
    """Prints and updates the wait indicator until done becomes True."""
    lastProgress = None
    indpos = 0
    ind = ["-", "\\", "|", "/"]
    while not self.done:
      if self.maxProgress == 0:
        sys.stdout.write("\r")
        sys.stdout.write(self._msg)
        sys.stdout.write(" ")
        sys.stdout.write(ind[indpos])
        sys.stdout.flush()
        indpos = (indpos + 1) % 4
      else:
        if self.progress != lastProgress:
          sys.stdout.write("\r")
          sys.stdout.write(self._msg)
          sys.stdout.write(" ")
          sys.stdout.write("{0:.0f}%".format(float(self.progress) / self.maxProgress * 100))
          sys.stdout.flush()
          lastProgress = self.progress
      sleep(0.03)
    sys.stdout.write("\r")
    sys.stdout.write(self._msg)
    sys.stdout.write(" Done.")
    sys.stdout.flush()
    print




# ========= FILESYSTEM INFORMATION ==============================================

def printInfoPairs(pairs):
  """Prints the info strings stored in a list of pairs, justified."""
  maxLeftLen = 0
  for p in pairs:
    if len(p[0]) > maxLeftLen:
      maxLeftLen = len(p[0])
  for p in pairs:
    if p[1]:
      if isinstance(p[1], list):
        print "{0}:".format(p[0])
        for message in p[1]:
          print "- {0}".format(message)
      else:
        print "{0}{1}".format(p[0].ljust(maxLeftLen+5, "."), p[1])
    else:
      print
      print p[0]
  print



def getGeneralInfo(fs):
  """Gets general information about the filesystem and generates a list of information pairs."""
  pairs = []
  if fs.fsType == "EXT2":
    pairs.append( ("GENERAL INFORMATION", None) )
    pairs.append( ("Ext2 revision", "{0}".format(fs.revision)) )
    pairs.append( ("Total space", "{0:.2f} MB ({1} bytes)".format(float(fs.totalSpace) / 1048576, fs.totalSpace)) )
    pairs.append( ("Used space", "{0:.2f} MB ({1} bytes)".format(float(fs.usedSpace) / 1048576, fs.usedSpace)) )
    pairs.append( ("Total space for files", "{0:.2f} MB ({1} bytes)".format(float(fs.totalFileSpace) / 1048576, fs.totalFileSpace)) )
    pairs.append( ("Block size", "{0} bytes".format(fs.blockSize)) )
    pairs.append( ("Num inodes", "{0}".format(fs.numInodes)) )
    pairs.append( ("Num block groups", "{0}".format(fs.numBlockGroups)) )

  else:
    raise FilesystemNotSupportedError()

  return pairs



def generateDetailedInfo(fs, showWaitIndicator = True):
  """Scans the filesystem to gather detailed information about space usage and returns
  a list of information pairs."""
  if fs.fsType == "EXT2":
    if showWaitIndicator:
      wait = WaitIndicatorThread("Scanning filesystem...")
      wait.start()
      try:
        report = fs.scanBlockGroups()
      finally:
        wait.done = True
      wait.join()
    else:
      report = fs.scanBlockGroups()

    pairs = []
    pairs.append( ("DETAILED STORAGE INFORMATION", None) )
    pairs.append( ("Num regular files", "{0}".format(report.numRegFiles)) )
    pairs.append( ("Num directories", "{0}".format(report.numDirs)) )
    pairs.append( ("Num symlinks", "{0}".format(report.numSymlinks)) )
    for i,groupReport in enumerate(report.groupReports):
      groupInfo = []
      groupInfo.append("Block bitmap location: {0}".format(groupReport.blockBitmapLocation))
      groupInfo.append("Inode bitmap location: {0}".format(groupReport.inodeBitmapLocation))
      groupInfo.append("Inode table location: {0}".format(groupReport.inodeTableLocation))
      groupInfo.append("Free inodes: {0}".format(groupReport.numFreeInodes))
      groupInfo.append("Free blocks: {0}".format(groupReport.numFreeBlocks))
      groupInfo.append("Directory inodes: {0}".format(groupReport.numInodesAsDirs))
      pairs.append( ("Block group {0}".format(i), groupInfo) )

  else:
    raise FilesystemNotSupportedError()

  return pairs



def generateIntegrityReport(fs, showWaitIndicator = True):
  """Runs an integrity report on the filesystem and returns the results as a list of
  information pairs."""
  if fs.fsType == "EXT2":
    if showWaitIndicator:
      wait = WaitIndicatorThread("Checking filesystem integrity...")
      wait.start()
      try:
        report = fs.checkIntegrity()
      finally:
        wait.done = True
      wait.join()
    else:
      report = fs.checkIntegrity()

    pairs = []
    pairs.append( ("INTEGRITY REPORT", None) )
    pairs.append( ("Contains magic number", "{0}".format(report.hasMagicNumber)) )
    pairs.append( ("Num superblock copies", "{0}".format(report.numSuperblockCopies)) )
    pairs.append( ("Superblock copy locations", "Block groups {0}".format(",".join(map(str,report.copyLocations)))) )
    pairs.append( ("Report messages", list(report.messages)) )

  else:
    raise FilesystemNotSupportedError()

  return pairs






# ========= SHELL COMMANDS ==============================================

def printShellHelp():
  """Prints a help screen for the shell, listing supported commands."""
  sp = 26
  rsp = 4
  print "Supported commands:"
  print "{0}{1}".format("pwd".ljust(sp), "Prints the current working directory.")
  print "{0}{1}".format("ls [-aFilRuU] [directory]".ljust(sp), "Prints the entries in the specified directory, or")
  print "{0}{1}".format("".ljust(sp), "the working directory if none is specified.")
  print "{0}{1}".format("".ljust(sp), "Optional flags:")
  print "{0}{1}{2}".format("".ljust(sp), "-a".ljust(rsp), "Lists hidden entries.")
  print "{0}{1}{2}".format("".ljust(sp), "-F".ljust(rsp), "Display character after each entry")
  print "{0}{1}{2}".format("".ljust(sp), "".ljust(rsp), "showing its type.")
  print "{0}{1}{2}".format("".ljust(sp), "-i".ljust(rsp), "Show each entry's inode number.")
  print "{0}{1}{2}".format("".ljust(sp), "-l".ljust(rsp), "Long list format.")
  print "{0}{1}{2}".format("".ljust(sp), "-R".ljust(rsp), "Lists entries recursively.")
  print "{0}{1}{2}".format("".ljust(sp), "-u".ljust(rsp), "Show last access time in long list format.")
  print "{0}{1}{2}".format("".ljust(sp), "-U".ljust(rsp), "Show creation time in long list format.")
  print
  print "{0}{1}".format("cd directory".ljust(sp), "Changes to the specified directory.")
  print
  print "{0}{1}".format("mkdir name".ljust(sp), "Makes a new directory with the specified name")
  print
  print "{0}{1}".format("rm [-r] filename".ljust(sp), "Removes the specified file or directory. The optional")
  print "{0}{1}".format("".ljust(sp), "-r flag forces recursive deletion of directories.")
  print
  print "{0}{1}".format("mv source dest".ljust(sp), "Moves the specified source file or directory to")
  print "{0}{1}".format("".ljust(sp), "the destination file or directory.")
  print
  print "{0}{1}".format("cp source dest".ljust(sp), "Copies the specified source file or directory to")
  print "{0}{1}".format("".ljust(sp), "the destination file or directory.")
  print
  print "{0}{1}".format("ln [-s] source name".ljust(sp), "Creates a link to the source with the specified ")
  print "{0}{1}".format("".ljust(sp), "name. If -s is specified, the new link is")
  print "{0}{1}".format("".ljust(sp), "symbolic. Hard links require source to exist.")
  print
  print "{0}{1}".format("chown uid filename".ljust(sp), "Changes the owner uid of the file to the given uid.")
  print "{0}{1}".format("chgrp gid filename".ljust(sp), "Changes the owner gid of the file to the given gid.")
  print "{0}{1}".format("chmod octmode filename".ljust(sp), "Changes the mode of the file to the one specified.")
  print
  print "{0}{1}".format("help".ljust(sp), "Prints this message.")
  print "{0}{1}".format("exit".ljust(sp), "Exits shell mode.")
  print


def printDirectory(directory, recursive, showAll, longList, showTypeCharacters, showInodeNums, useTimeAccess, useTimeCreation):
  """Prints the specified directory according to the given parameters."""
  if not directory.fsType == "EXT2":
    raise FilesystemNotSupportedError()

  q = deque([])
  q.append(directory)
  while len(q) > 0:
    d = q.popleft()
    files = []
    maxInodeLen = 0
    maxSizeLen = 0
    maxUidLen = 0
    maxGidLen = 0
    for f in d.files():
      if not showAll and f.name.startswith("."):
        continue
      if f.isDir and f.name != "." and f.name != "..":
        if recursive:
          q.append(f)
      files.append(f)
      if longList:
        maxInodeLen = max(len(str(f.inodeNum)), maxInodeLen)
        maxSizeLen = max(len(str(f.size)), maxSizeLen)
        maxUidLen = max(len(str(f.uid)), maxUidLen)
        maxGidLen = max(len(str(f.gid)), maxGidLen)

    files = sorted(files, key=lambda f: f.name)

    if recursive:
      print "{0}:".format(d.absolutePath)

    for f in files:

      if not longList:
        name = f.name
        if showTypeCharacters:
          if f.isDir:
            name = "{0}/".format(name)
          elif f.isSymlink:
            name = "{0}@".format(name)
          elif f.isRegular and f.isExecutable:
            name = "{0}*".format(name)
        print name

      else:
        inodeStr = ""
        name = f.name
        if showTypeCharacters:
          if f.isDir:
            name = "{0}/".format(name)
          elif f.isSymlink:
            name = "{0}@".format(name)
          elif f.isRegular and f.isExecutable:
            name = "{0}*".format(name)

        if f.isSymlink:
          name = "{0} -> {1}".format(name, f.getLinkedPath())


        if showInodeNums:
          inodeStr = "{0} ".format(f.inodeNum).rjust(maxInodeLen + 1)

        numLinks = "{0}".format(f.numLinks).rjust(2)
        uid = "{0}".format(f.uid).rjust(maxUidLen)
        gid = "{0}".format(f.gid).rjust(maxGidLen)
        size = "{0}".format(f.size).rjust(maxSizeLen)
        if useTimeAccess:
          time = f.timeAccessed.ljust(17)
        elif useTimeCreation:
          time = f.timeCreated.ljust(17)
        else:
          time = f.timeModified.ljust(17)

        print "{0}{1} {2} {3} {4} {5} {6} {7}".format(inodeStr, f.modeStr, numLinks, uid, gid, size, time, name)
    print




def removeFile(parentDir, rmFile, recursive = False):
  """Removes the specified file or directory from the given directory."""

  if recursive and rmFile.isDir:

    def getFilesToRemove(rmDir):
      filesToRemove = deque([])
      for f in rmDir.files():
        if f.name == "." or f.name == "..":
          continue
        if f.isDir:
          filesToRemove.extend(getFilesToRemove(f))
        filesToRemove.append((rmDir, f))
      return filesToRemove

    for parent,f in getFilesToRemove(rmFile):
      parent.removeFile(f)

  parentDir.removeFile(rmFile)



def copyFile(fromFile, toDir, newFilename = None, showWaitIndicator = True):
  """Copies the specified file into the new directory."""
  if newFilename:
    name = newFilename
  else:
    name = fromFile.name

  if fromFile.isDir:
    raise FilesystemError("Cannot copy directory.")

  uid = fromFile.uid
  gid = fromFile.gid
  creationTime = fromFile.timeCreatedEpoch
  modTime = fromFile.timeModifiedEpoch
  accessTime = fromFile.timeAccessedEpoch
  permissions = fromFile.permissions
  newFile = toDir.makeRegularFile(name, uid, gid, creationTime, modTime, accessTime, permissions)

  def __copy(wait = None):
    copied = 0
    for block in fromFile.blocks():
      newFile.write(block)
      copied += len(block)
      if wait:
        wait.progress += len(block)
    return copied

  if showWaitIndicator:
    wait = WaitIndicatorThread("Copying ...")
    wait.maxProgress = fromFile.size
    wait.start()
    try:
      transferStart = clock()
      written = __copy(wait)
      transferTime = clock() - transferStart
    finally:
      wait.done = True
    wait.join()
  else:
    transferStart = clock()
    written = __copy()
    transferTime = clock() - transferStart

  if transferTime > 0:
    mbps = float(written) / (1024*1024) / transferTime
  else:
    mbps = 0
  print "Copied {0} bytes at {1:.2f} MB/sec.".format(written, mbps)




def moveFile(fromFile, toDir, newFilename = None):
  """Moves the specified file into the new directory."""
  fromFile.parentDir.moveFile(fromFile, toDir, newFilename)






def getFileObject(fs, directory, path, followSymlinks):
  """Looks up the file object specified by the given absolute path or the path relative to the specified directory."""
  try:
    if path == "/":
      fileObject = fs.rootDir
    elif path.startswith("/"):
      fileObject = fs.rootDir.getFileAt(path[1:], followSymlinks)
    else:
      fileObject = directory.getFileAt(path, followSymlinks)
  except FileNotFoundError:
    raise FilesystemError("{0} does not exist.".format(path))
  if fileObject.absolutePath == directory.absolutePath:
    fileObject = directory
  return fileObject


def parseNewPath(fs, directory, path):
  """Parses the given absolute path or path relative to the specified directory and returns the name of a file
  and its parent directory."""
  parentDir = directory
  if path.startswith("/"):
    path = path[1:]
    parentDir = fs.rootDir
    if parentDir.absolutePath == directory.absolutePath:
      parentDir = directory
  if "/" in path:
    name = path[path.rindex("/")+1:]
    parentDir = getFileObject(fs, directory, path[:path.rindex("/")], True)
  else:
    name = path
  return (parentDir, name)


def shell(fs):
  """Enters a command-line shell with commands for operating on the specified filesystem."""
  workingDir = fs.rootDir
  print "Entered shell mode. Type 'help' for shell commands."


  def __parseInput(inputline):
    if inputline.endswith("\\") and not inputline.endswith("\\\\"):
      raise ShellError("Invalid escape sequence.")

    parts = deque(inputline.split())
    if len(parts) == 0:
      raise ShellError("No command specified.")
    cmd = parts.popleft()
    flags = []
    parameters = []

    while len(parts) > 0:
      part = parts.popleft()

      if "\\" in part and not part.endswith("\\"):
        raise ShellError("Invalid escape sequence.")

      if part.startswith("-") and len(parameters) == 0:
        flags.extend(list(part[1:]))

      elif part.startswith("\"") or part.startswith("\'"):
        quoteChar = part[0]
        param = part[1:]
        nextPart = part
        while not nextPart.endswith(quoteChar) and len(parts) > 0:
          nextPart = parts.popleft()
          param = "{0} {1}".format(param, nextPart)
        if not param.endswith(quoteChar):
          raise ShellError("No closing quotation found.")
        parameters.append(param[:-1])

      elif part.endswith("\\"):
        param = ""
        nextPart = part
        while nextPart.endswith("\\") and len(parts) > 0:
          param = "{0} {1}".format(param, nextPart[:-1])
          nextPart = parts.popleft()
        param = "{0} {1}".format(param, nextPart)
        parameters.append(param.strip())

      else:
        parameters.append(part)

    return (cmd, flags, parameters)


  while True:
    inputline = raw_input(": '{0}' >> ".format(workingDir.absolutePath)).rstrip()
    if len(inputline) == 0:
      continue

    try:
      parsed = __parseInput(inputline)
      cmd = parsed[0]
      flags = parsed[1]
      parameters = parsed[2]

      if cmd == "help":
        printShellHelp()

      elif cmd == "exit":
        break

      elif cmd == "pwd":
        print workingDir.absolutePath

      elif cmd == "ls":
        if len(parameters) == 0:
          printDirectory(workingDir, "R" in flags, "a" in flags, "l" in flags, "F" in flags,
                         "i" in flags, "u" in flags, "U" in flags)
        elif len(parameters) == 1:
          lsDir = getFileObject(fs, workingDir, parameters[0], True)
          printDirectory(lsDir, "R" in flags, "a" in flags, "l" in flags, "F" in flags,
                         "i" in flags, "u" in flags, "U" in flags)
        else:
          raise ShellError("Invalid parameters.")

      elif cmd == "cd":
        if len(parameters) != 1:
          raise ShellError("Invalid parameters.")
        cdDir = getFileObject(fs, workingDir, parameters[0], True)
        if not cdDir.isDir:
          raise FilesystemError("Not a directory.")
        workingDir = cdDir


      elif cmd == "mkdir":
        if len(parameters) != 1:
          raise ShellError("Invalid parameters.")
        parsed = parseNewPath(fs, workingDir, parameters[0])
        parentDir = parsed[0]
        name = parsed[1]
        parentDir.makeDirectory(name)


      elif cmd == "rm":
        if len(parameters) != 1:
          raise ShellError("Invalid parameters.")
        parsed = parseNewPath(fs, workingDir, parameters[0])
        parentDir = parsed[0]
        name = parsed[1]
        rmFile = parentDir.getFileAt(name, False)
        removeFile(parentDir, rmFile, "r" in flags)


      elif cmd == "mv" or cmd == "cp":
        if len(parameters) != 2:
          raise ShellError("Invalid parameters.")
        parsed = parseNewPath(fs, workingDir, parameters[0])
        parentDir = parsed[0]
        name = parsed[1]
        fromFile = parentDir.getFileAt(name, False)
        parsed = parseNewPath(fs, workingDir, parameters[1])
        toDir = parsed[0]
        name = parsed[1]

        try:
          nextDir = toDir.getFileAt(name)
          if nextDir.isSymlink:
            try:
              while nextDir.isSymlink:
                nextDir = fs.rootDir.getFileAt(nextDir.getLinkedPath()[1:])
            except FileNotFoundError:
              pass
          if nextDir.isDir:
            toDir = nextDir
            name = ""
        except FileNotFoundError:
          pass

        if len(name) == 0:
          name = None
        if cmd == "mv":
          moveFile(fromFile, toDir, name)
        elif cmd == "cp":
          copyFile(fromFile, toDir, name)


      elif cmd == "ln":
        if len(parameters) != 2:
          raise ShellError("Invalid parameters.")
        parsed = parseNewPath(fs, workingDir, parameters[1])
        destDir = parsed[0]
        name = parsed[1]
        if len(name) == 0:
          raise ShellError("No name specified.")
        if "s" in flags:
          destDir.makeSymbolicLink(name, parameters[0])
        else:
          parsed = parseNewPath(fs, workingDir, parameters[0])
          parentDir = parsed[0]
          name = parsed[1]
          sourceFile = parentDir.getFileAt(name, False)
          destDir.makeHardLink(name, sourceFile)


      elif cmd == "chown":
        if len(parameters) != 2:
          raise ShellError("Invalid parameters.")
        uid = int(parameters[0])
        name = parameters[1]
        if len(name) == 0:
          raise ShellError("No filename specified.")
        chFile = getFileObject(fs, workingDir, name, True)
        chFile.uid = uid


      elif cmd == "chgrp":
        if len(parameters) != 2:
          raise ShellError("Invalid parameters.")
        gid = int(parameters[0])
        name = parameters[1]
        if len(name) == 0:
          raise ShellError("No filename specified.")
        chFile = getFileObject(fs, workingDir, name, True)
        chFile.gid = gid


      elif cmd == "chmod":
        if len(parameters) != 2:
          raise ShellError("Invalid parameters.")
        octmode = parameters[0]
        try:
          mode = (int(octmode[0]) & 0x7) << 6
          mode |= (int(octmode[1]) & 0x7) << 3
          mode |= (int(octmode[2]) & 0x7)
        except:
          raise ShellError("Invalid mode specified.")
        name = parameters[1]
        if len(name) == 0:
          raise ShellError("No filename specified.")
        chFile = getFileObject(fs, workingDir, name, True)
        chFile.permissions = mode


      else:
        raise ShellError("Command not recognized.")
    except ShellError as e:
      print e
      continue
    except FileNotFoundError:
      print "File not found."
      continue
    except FilesystemError as e:
      print e
      continue





# ========= FILE TRANSFER ==============================================

def fetchFile(fs, srcFilename, destDirectory, showWaitIndicator = True):
  """Fetches the specified file from the filesystem image and places it in
  the local destination directory."""
  if not fs.fsType == "EXT2":
    raise FilesystemNotSupportedError()

  filesToFetch = []
  if srcFilename.endswith("/*"):
    directory = fs.rootDir.getFileAt(srcFilename[:-1])
    destDirectory = "{0}/{1}".format(destDirectory, directory.name)
    for f in directory.files():
      if f.isRegular:
        filesToFetch.append(f.absolutePath)
  else:
    filesToFetch.append(srcFilename)

  if len(filesToFetch) == 0:
    raise FilesystemError("No files exist in the specified directory.")

  if not os.path.exists(destDirectory):
    print "Making directory {0}".format(destDirectory)
    os.makedirs(destDirectory)

  for srcFilename in filesToFetch:
    try:
      srcFile = fs.rootDir.getFileAt(srcFilename)
    except FileNotFoundError:
      raise FilesystemError("The source file cannot be found on the filesystem image.")

    if not srcFile.isRegular:
      raise FilesystemError("The source path does not point to a regular file.")

    srcPath = "{0}/{1}".format(destDirectory, srcFile.name)
    try:
      outFile = open(srcPath, "wb")
    except:
      raise FilesystemError("Cannot access specified destination directory.")

    def __read(wait = None):
      readCount = 0
      with outFile:
        for block in srcFile.blocks():
          outFile.write(block)
          readCount += len(block)
          if wait:
            wait.progress += len(block)
      return readCount

    if showWaitIndicator:
      wait = WaitIndicatorThread("Fetching {0}...".format(srcFilename))
      wait.maxProgress = srcFile.size
      wait.start()
      try:
        transferStart = clock()
        readCount = __read(wait)
        transferTime = clock() - transferStart
      finally:
        wait.done = True
      wait.join()
    else:
      transferStart = clock()
      readCount = __read()
      transferTime = clock() - transferStart

    if transferTime > 0:
      mbps = float(readCount) / (1024*1024) / transferTime
    else:
      mbps = 0
    print "Read {0} bytes at {1:.2f} MB/sec.".format(readCount, mbps)

    os.utime(srcPath, (srcFile.timeAccessedEpoch, srcFile.timeModifiedEpoch))

  print



def putFile(fs, srcFilename, destDirectory, showWaitIndicator = True):
  """Puts the specified local file to the specified destination directory on the filesystem image."""
  if not fs.fsType == "EXT2":
    raise FilesystemNotSupportedError()

  destFilename = srcFilename[srcFilename.rfind("/")+1:]
  directory = getFileObject(fs, fs.rootDir, destDirectory, False)

  if not os.path.exists(srcFilename):
    raise FilesystemError("Source file does not exist.")

  if not os.path.isfile(srcFilename):
    raise FilesystemError("Source is not a file.")

  uid = os.stat(srcFilename).st_uid
  gid = os.stat(srcFilename).st_gid
  modTime = int(os.stat(srcFilename).st_mtime)
  accessTime = int(os.stat(srcFilename).st_atime)
  try:
    creationTime = int(os.stat(srcFilename).st_birthtime)
  except AttributeError:
    creationTime = modTime
  newFile = directory.makeRegularFile(destFilename, uid, gid, creationTime, modTime, accessTime)

  inFile = open(srcFilename, "rb")
  def __write(wait = None):
    written = 0
    with inFile:
      inFile.seek(0, 2)
      length = inFile.tell()
      if wait:
        wait.maxProgress = length
        wait.start()
      inFile.seek(0)
      while written < length:
        byteString = inFile.read(fs.blockSize)
        newFile.write(byteString)
        written += len(byteString)
        if wait:
          wait.progress += len(byteString)
    return written

  if showWaitIndicator:
    wait = WaitIndicatorThread("Putting {0} at {1}...".format(srcFilename, newFile.absolutePath))
    try:
      transferStart = clock()
      written = __write(wait)
      transferTime = clock() - transferStart
    finally:
      wait.done = True
    wait.join()
  else:
    transferStart = clock()
    written = __write()
    transferTime = clock() - transferStart

  if transferTime > 0:
    mbps = float(written) / (1024*1024) / transferTime
  else:
    mbps = 0
  print "Wrote {0} bytes at {1:.2f} MB/sec.".format(written, mbps)





# ========= MAIN APPLICATION ==============================================

def printHelp():
  """Prints the help screen for the main application, with usage and command options."""
  sp = 26
  print "Usage: {0} image_file options".format(sys.argv[0])
  print
  print "Options:"
  print "{0}{1}".format("-s".ljust(sp), "Enters shell mode.")
  print "{0}{1}".format("-h".ljust(sp), "Prints this message and exits.")
  print "{0}{1}".format("-f filepath [hostdir]".ljust(sp), "Fetches the specified file from the filesystem")
  print "{0}{1}".format("".ljust(sp), "into the optional host directory. If no directory")
  print "{0}{1}".format("".ljust(sp), "is specified, defaults to the current directory.")
  print
  print "{0}{1}".format("-p hostfile destpath".ljust(sp), "Puts the specified host file into the specified")
  print "{0}{1}".format("".ljust(sp), "directory on the filesystem.")
  print
  print "{0}{1}".format("-i".ljust(sp), "Prints general information about the filesystem.")
  print "{0}{1}".format("-d".ljust(sp), "Scans the filesystem and prints detailed space")
  print "{0}{1}".format("".ljust(sp), "usage information.")
  print
  print "{0}{1}".format("-c".ljust(sp), "Checks the filesystem's integrity and prints a")
  print "{0}{1}".format("".ljust(sp), "detailed integrity report.")
  print
  print "{0}{1}".format("-n blockSize numBlocks".ljust(sp), "Creates the specified image file as a new ext2")
  print "{0}{1}".format("".ljust(sp), "image with the specified parameters.")
  print
  print "{0}{1}".format("-w".ljust(sp), "Suppress the wait indicator that is typically")
  print "{0}{1}".format("".ljust(sp), "shown for long operations. This is useful when")
  print "{0}{1}".format("".ljust(sp), "redirecting the output of this program.")
  print


def run(args, fs):
  """Runs the program on the specified filesystem with the given command line arguments."""
  showHelp = ("-h" in args)
  enterShell = ("-s" in args)
  showGeneralInfo = ("-i" in args)
  showDetailedInfo = ("-d" in args)
  showIntegrityCheck = ("-c" in args)
  suppressIndicator = ("-w" in args)
  fetch = ("-f" in args)
  put = ("-p" in args)

  if showHelp or not (showGeneralInfo or enterShell or showDetailedInfo or showIntegrityCheck or fetch or put):
    printHelp()
    quit()

  else:
    info = []
    if showGeneralInfo:
      info.extend(getGeneralInfo(fs))
    if showDetailedInfo:
      info.extend(generateDetailedInfo(fs, not suppressIndicator))
    if showIntegrityCheck:
      info.extend(generateIntegrityReport(fs, not suppressIndicator))
    if len(info) > 0:
      printInfoPairs(info)

    if put:
      srcNameIndex = args.index("-p") + 1
      destNameIndex = srcNameIndex + 1
      if len(args) <= srcNameIndex:
        print "Error! No source file specified."
      elif len(args) <= destNameIndex:
        print "Error! No destination directory specified."
      else:
        try:
          putFile(fs, args[srcNameIndex], args[destNameIndex], not suppressIndicator)
        except FilesystemError as e:
          print "Error! {0}".format(e)

    if fetch:
      srcNameIndex = args.index("-f") + 1
      destNameIndex = srcNameIndex + 1
      if len(args) <= srcNameIndex:
        print "Error! No source file specified."
      else:
        if len(args) <= destNameIndex:
          destDirectory = "."
        elif args[destNameIndex][0] == "-":
          destDirectory = "."
        else:
          destDirectory = args[destNameIndex]
        try:
          fetchFile(fs, args[srcNameIndex], destDirectory, not suppressIndicator)
        except FilesystemError as e:
          print "Error! {0}".format(e)

    if enterShell:
      shell(fs)



def main():
  """Main entry point of the application."""
  fs = None
  args = list(sys.argv)
  if len(args) < 3:
    printHelp()
    quit()
  elif args[1][0] == "-":
    printHelp()
    quit()
  else:
    filename = args[1]
    del args[0:1]

    if "-n" in args:
      try:
        i = args.index("-n")
        if len(args) < i + 3:
          raise ShellError("Invalid parameters. Usage: -n blockSize numBlocks.")
        imageFilename = filename
        blockSize = int(args[i+1])
        numBlocks = int(args[i+2])
        print "Making new filesystem {0} with blocksize {1} and {2} blocks...".format(imageFilename, blockSize, numBlocks)
        Ext2Filesystem.makeFromNewImageFile(filename, blockSize, numBlocks)
        print "Done."
      except ShellError as e:
        print "Error! {0}".format(e)
        print "Filesystem creation failed."
      except FilesystemError as e:
        print "Error! {0}".format(e)
        print "Filesystem creation failed."

    else:
      try:
        fs = Ext2Filesystem.fromImageFile(filename)
        with fs:
          run(args, fs)
      except IOError:
        print "Could not read image file."



main()
