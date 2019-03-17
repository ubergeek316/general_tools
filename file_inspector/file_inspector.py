#!/usr/bin/python3

# Name: Cross-Platform (Windows and Linux) File Inspector (Metadata Analyzer)
# Author: Jsaon Savitt
# Version: 0.1 (alpha)
# Description: A Python cross-platform (Windows and Linux) file types type inspectors, displays detailed OS attributes
#              and metadata on different file types, including file hashes, file size, mime type (via magic number
#              inspection), and path information.
#              - includes: EXIF, compressed files, audio, video, images

# Requires: Python 3.7 (or higher) [may work on eariler versions, but not tested]
# requires the following python modules to be installed
# pip install filetype
# pip install Pillow
# pip install pywin32

# Example:
# file_inspector.py .\testarea\test.aif

# - File Type:      FILE
# - Accesed:        2019-03-14 22:06:25
# - Modified:       2019-03-14 22:06:28
# - Created:        2019-03-14 22:06:25
# - Full Path:      C:\Users\username\fileinpector\testarea\test.aif
# - File Name:      testarea\test.aif
# - File Ext:       aif
# - SHA256:         eb26bc07c0b021df81854c81b2e577c1da355ca8146c9ab2c91709bbcf03f104
# - MD5:            15900edaef171c4ae529a8dcd42055fe
# - File Size:      1210154  (bytes)
# - Windows File Attributes
#   - FILE_ATTRIBUTE_ARCHIVE
# - File Info:
#   - Type:          aiff
#   - Frame Rate:    48000
#   - N Channels:    2
#   - N Frames:      302640
#   - Sample Width:  16


import os, platform, stat, sys, time
# Used to generate a hash of the contents of a file
import hashlib
# Extracts (images)  the 'magic numbers' signature
import imghdr
# Extracts (sound)  the 'magic numbers' signature
import sndhdr
# Used for extracting the TAR file information
import tarfile
# Used for extracting the ZIP file information
from zipfile import ZipFile
# This modules lookup user and group IDs in Linux
# Note: These built-in modules don't load under Windows
if platform.system() == 'Linux':
    import grp, pwd
from datetime import datetime
# Extracts (multimedia) the 'magic numbers' signature
# module 'filetype':
# Install: pip install filetype
# reference: https://pypi.org/project/filetype/
import filetype
# Used for extracting the EXIF data
# module 'pillow' (Python Image Library)
# Install: pip install Pillow
# reference: https://pypi.org/project/Pillow/
# documents: https://pillow.readthedocs.io/en/stable/index.html
from PIL import Image
from PIL import ExifTags
# Used for checking file permissions
# 'PYWIN32' module (used for accessing Windows OS information)
# To install:
# - pip install pywin32
# References:
# - https://pypi.org/project/pywin32/
# Documentation
# - http://timgolden.me.uk/pywin32-docs/contents.html
import win32con
import win32api


# Extracts the EXIF data in an image file
def get_exif_data(filename):
    try:
        exifData = {}
        # Opens the image file and extras the data
        image_file = Image.open(filename)
        exifDataRaw = image_file._getexif()
        # Iterates through the EXIF data from the image
        for tag, value in exifDataRaw.items():
            # Extracts the EXIF data from the image
            decodedTag = ExifTags.TAGS.get(tag, tag)
            # Skips the 'MakerNote' (lots of binary data) and 'GPSInfo' tags (decoded in a previous loop)
            if decodedTag != 'MakerNote':
                exifData[decodedTag] = value
        return exifData
    except Exception:
        return False


# Displays the contents of a TAR file
def get_tar_info(filename):
    # Opens the TAR file in READ mode
    tar_file = tarfile.open(filename, 'r')
    # Formats the output
    print('Filename')
    print('Modified                  Mode      Type        Size (bytes)')
    # Iterates through files in the TAR.
    for member_info in tar_file.getmembers():
        print(member_info.name)
        # Converts the contents into a table format
        print('{: <25} {: <10} {: <10} {: <10}'.format(time.ctime(member_info.mtime), oct(member_info.mode).lstrip('0o'), str(member_info.type), member_info.size))


# Displays the contents of a ZIP file
def get_zip_info(filename):
    # Opens the ZIP file in READ mode
    zf = ZipFile(filename)
    # Formats the output
    print('Filename')
    print('System     Version  Compressed      Expanded        Date        CRC')
    # Iterates through files in the ZIP.
    for info in zf.infolist():
        print(info.filename)
        # Converts the contents into a table format
        print('{: <10} {: <8} {: <15} {: <15} {: <10}  {: <15}'.format(info.create_system == 3
                and 'Linux' or 'Windows', info.create_version, info.compress_size, info.file_size,
                (str(info.date_time[1])+'-'+str(info.date_time[2])+'-'+str(info.date_time[0])), info.CRC))

# Displays infomation about an image file
def get_image_info(filename):
    image = Image.open(filename)
    print('- Image Attribute:')
    print('  - Information   ', image.info)
    #print('  - Format:      ', image.format)
    print('  - Size:        ', image.size)
    print('  - Height:      ', image.height)
    print('  - Width:       ', image.width)
    print('  - Mode:        ', image.mode)
    print('  - Description: ', image.format_description)
    #print('  - MIME Type:   ', image.get_format_mimetype())


# Generates a SHA256 hash for a file object
def md5_checksum(filename, blocksize=65536):
    # Initialize library
    md5 = hashlib.md5()
    # Opens file and reads/hash the contents
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(blocksize), b''):
            md5.update(block)
    return md5.hexdigest()


# Generates a SHA256 hash for a file object
def sha256_checksum(filename, block_size=65536):
    # Initialize library
    sha256 = hashlib.sha256()
    # Opens file and reads/hash the contents
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha256.update(block)
    return sha256.hexdigest()


# Displays Windows Attributes
def windows_file_attributes(filename):
    # Iterates File Attributes
    attrs = win32api.GetFileAttributes(filename)
    # Tests each attribute against a known list of flags
    print('- Windows File Attributes')
    if (attrs & win32con.FILE_ATTRIBUTE_READONLY):
        print('  - FILE_ATTRIBUTE_READONLY')
    if (attrs & win32con.FILE_ATTRIBUTE_HIDDEN):
        print('  - FILE_ATTRIBUTE_HIDDEN')
    if (attrs & win32con.FILE_ATTRIBUTE_SYSTEM):
        print('  - FILE_ATTRIBUTE_SYSTEM')
    if (attrs & win32con.FILE_ATTRIBUTE_DIRECTORY):
        print('  - FILE_ATTRIBUTE_DIRECTORY')
    if (attrs & win32con.FILE_ATTRIBUTE_ARCHIVE):
        print('  - FILE_ATTRIBUTE_ARCHIVE')
    if (attrs & win32con.FILE_ATTRIBUTE_DEVICE):
        print('  - FILE_ATTRIBUTE_DEVICE')
    if (attrs & win32con.FILE_ATTRIBUTE_NORMAL):
        print('  - FILE_ATTRIBUTE_NORMAL')
    if (attrs & win32con.FILE_ATTRIBUTE_TEMPORARY):
        print('  - FILE_ATTRIBUTE_TEMPORARY')
    if (attrs & win32con.FILE_ATTRIBUTE_SPARSE_FILE):
        print('  - FILE_ATTRIBUTE_SPARSE_FILE')
    if (attrs & win32con.FILE_ATTRIBUTE_REPARSE_POINT):
        print('  - FILE_ATTRIBUTE_REPARSE_POINT')
    if (attrs & win32con.FILE_ATTRIBUTE_COMPRESSED):
        print('  - FILE_ATTRIBUTE_COMPRESSED')
    if (attrs & win32con.FILE_ATTRIBUTE_OFFLINE):
        print('  - FILE_ATTRIBUTE_OFFLINE')
    if (attrs & win32con.FILE_ATTRIBUTE_TEMPORARY):
        print('  - FILE_ATTRIBUTE_TEMPORARY')
    if (attrs & win32con.FILE_ATTRIBUTE_NOT_CONTENT_INDEXED):
        print('  - FILE_ATTRIBUTE_NOT_CONTENT_INDEXED')
    if (attrs & win32con.FILE_ATTRIBUTE_ENCRYPTED):
        print('  - FILE_ATTRIBUTE_ENCRYPTED')
    if (attrs & win32con.FILE_ATTRIBUTE_TEMPORARY):
        print('  - FILE_ATTRIBUTE_VIRTUAL')


# Displays file information/attributes
def file_info(filename):
    # Expands the user's home directory for the file object
    # Turned off right now, not using it.  Keeping for reference.
    #filename = pathlib.Path(os.path.expanduser('~') + fileobject)
    # Checks if the file object exists
    if os.path.exists(filename) == True:
        # Checks the type of file:
        if os.path.islink(filename) == True:
            print('- File Type:      LINK')
        if os.path.isfile(filename) == True:
            print('- File Type:      FILE')
        if os.path.isdir(filename) == True:
            print('- File Type:      DIRECTORY')
        if os.path.islink(filename) == True:
            print('- File Type:      LINK')
        if os.path.ismount(filename) == True:
            print('- File Type:      MOUNT')
        # File Times
        print ('- Accesed:       ', datetime.fromtimestamp(os.path.getatime(filename)).strftime('%Y-%m-%d %H:%M:%S'))
        print ('- Modified:      ', datetime.fromtimestamp(os.path.getmtime(filename)).strftime('%Y-%m-%d %H:%M:%S'))
        print ('- Created:       ', datetime.fromtimestamp(os.path.getctime(filename)).strftime('%Y-%m-%d %H:%M:%S'))
        # File Path
        print('- Full Path:     ', os.path.realpath(filename))
        if os.path.isfile(filename) == True:
            print('- File Name:     ', os.path.relpath(filename))
            print('- File Ext:      ', filename.split('.')[-1])
            object_hash = sha256_checksum(filename)
            print('- SHA256:        ', object_hash)
            object_hash = md5_checksum(filename)
            print('- MD5:           ', object_hash)
        # Object Size
        print('- File Size:     ', os.path.getsize(filename), ' (bytes)')
        # Displays Windows Attributes
        if platform.system() == 'Windows':
            windows_file_attributes(filename)
        # Object Statistics (useful only in linux)
        if platform.system() == 'Linux':
            os_stat = os.stat(filename)
            print('- Inode Protect: ', os_stat.st_mode)
            print('- Inode Number:  ', os_stat.st_ino)
            print('- Device Inode:  ', os_stat.st_dev)
            print('- # Hard Links:  ', os_stat.st_nlink)
            print('- Owner UserID:  ', os_stat.st_uid, ' (', pwd.getpwuid(os_stat.st_uid).pw_name, ')')
            print('- Owner GroupID: ', os_stat.st_gid, ' (', grp.getgrgid(os_stat.st_uid).gr_name, ')')
            print('- File Perms:    ', oct(stat.S_IMODE(os_stat[stat.ST_MODE])).lstrip('0o'))
        # Checks the 'magic numbers' signature (Multimedia)
        file_type = filetype.guess(filename)
        if file_type != None and os.path.isfile(filename) == True:
            print('- MIME Ext.:     ', file_type.extension)
            print('- MIME Type:     ', file_type.mime)
        # Secondary checks of the 'magic numbers' signature (image files)
        # Note: Disabled because it was not offering any additional value
        #file_type = imghdr.what(filename)
        #if file_type != None and os.path.isfile(filename) == True:
            #print('*** MIME Ext.: ', file_type)
        # If it is a ZIP file, the contents are displayed
        file_ext = filename.split('.')[-1]
        # Secondary checks of the 'magic numbers' signature (sound files)
        supported_file_types = ['MP4', 'WAV', 'AIF']
        if file_ext.upper() in supported_file_types:
            file_type = sndhdr.what(filename)
            print('- File Info:')
            print('  - Type:         ', file_type.filetype)
            print('  - Frame Rate:   ', file_type.framerate)
            print('  - N Channels:   ', file_type.nchannels)
            print('  - N Frames:     ', file_type.nframes)
            print('  - Sample Width: ', file_type.sampwidth)
        # File types that use the TAR format
        supported_file_types = ['TAR']
        if file_ext.upper() in supported_file_types:
            get_tar_info(filename)
        # File types that use the EXIF data
        # More information: https://en.wikipedia.org/wiki/Exif
        supported_file_types = ['JPG', 'TIF', 'TIFF', 'WAV']
        # Checks the file extension if it is image file
        if file_ext.upper() in supported_file_types:
            exif_data = get_exif_data(filename)
            if exif_data != False:
                print('------')
                for key, value in exif_data.items():
                    # Decodes the GPS data
                    if key == 'GPSInfo':
                        for gps_key, gps_value in value.items():
                            print(ExifTags.GPSTAGS[gps_key], '', gps_value)
                    else:
                        print(key, ': ', value)
                print('------')
        # Displays infomation about an image file
        supported_file_types = ['JPG', 'JPEG', 'TIF', 'TIFF', 'WMF', 'EMF', 'BMP', 'GIF', 'PNG']
        # Checks the file extension if it is image file
        if file_ext.upper() in supported_file_types:
            get_image_info(filename)
        # File types that use the ZIP format
        supported_file_types = ['ZIP', 'DOCX', 'XLSX', 'PPTX', 'JAR']
        # Checks the file extension if it is zip file
        if file_ext.upper() in supported_file_types:
            print('------')
            get_zip_info(filename)
            print('------')
    else:
        print('Error: File Doesn\'t Exist.')
    print('-----------------------------------')


if __name__ == '__main__':
    try:
        # Accepts arguments from the command line
        file_info(str(sys.argv[1]))
    # Exception Handling
    except Exception as e:
        # More Information: https://docs.python.org/3/library/exceptions.html
        print('------')
        print('Error: line {}:'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
        print('------')
