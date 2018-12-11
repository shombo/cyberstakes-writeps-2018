import os
from pwn import *
from base64 import b64decode
from StringIO import StringIO
from fnmatch import fnmatch
from zipfile import ZipFile


def find_files(directory, pattern):
    for root, dirs, files in os.walk(directory):
        for basename in files:
            if fnmatch(basename, pattern):
                filename = os.path.join(root, basename)
                yield filename


if __name__ == '__main__':
    cwd = os.getcwd()
    #sh = process('/bin/sh')
    #sh.sendline('cd ' + cwd)
    #sh.sendline('msoffcrypto-tool -p supersecret word_up.docx word_up_decrypted.docx')
    # unzip the unencrypted .docx
    #sh.sendline('unzip word_up_decrypted.docx -d word_up_decrypted')

    word_zip_dir = os.path.join(cwd, 'word_up_decrypted')
    # make a dir to store all the gfxdata
    gfxdata_dir = os.path.join(cwd, 'gfxdata')
    if not os.path.exists(gfxdata_dir):
        os.makedirs(gfxdata_dir)
    gfxdata_count = 0
    # walk all files in decrypted .docx. Look for gfxdata.
    for filename in find_files(word_zip_dir, '*'):
        with open(filename, 'rt') as f:
            matches = re.findall('gfxdata="[A-Za-z0-9+/=]*"', f.read().replace('&#xA;', ''))
            if matches:
                for match in matches:
                    # decode gfxdata and save to .zip
                    zip = 'gfxdata'+str(gfxdata_count)+'.zip'
                    gfxdata_count += 1
                    with open(os.path.join(gfxdata_dir, zip), 'wb') as f2:
                        f2.write(b64decode(match[9:-1]))
    # walk gfxdata_dir, unzip all zip files.
    for filename in find_files(gfxdata_dir, '*.zip'):
        with ZipFile(filename, 'r') as zip_ref:
            zip_ref.extractall(os.path.join(gfxdata_dir, filename[:-4]))
    # search all files for flag
    for filename in find_files(gfxdata_dir, '*'):
        with open(filename, 'rt') as f:
            match = re.search('ACI{.*}', f.read())
            if match:
                print(match.group())
                break
