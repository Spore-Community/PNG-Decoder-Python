#!/usr/bin/python

import os, sys, optparse, re, time, zlib, struct, random
from PIL import Image

version = "v1.0 (2008-06-27)"

class Decoder(object):
    def __init__(self, data):
        self.data = data
        self.hash = 0x811c9dc5
        self.next_pos = 0x0b400

    def __iter__(self):
        return self

    def next(self):
            byte = 0    #this look terrible, but it's optimized
            for i in xrange(8):
                n = self.next_pos
                d = self.data[n]
                e = (self.hash * 0x1000193) & 0xffffffff
                self.hash = e ^ ((n & 7) | (d & 0xf8))
                e = ((d&1) << 7) ^ ((self.hash & 0x8000) >> 8)
                byte = (byte >> 1) | e
                self.next_pos = (n >> 1) ^ (0x0b400 & -(n & 1))
                    
                if (self.next_pos == 0x0b400):
                    raise StopIteration

            return byte

    def get_data(self):
        return ''.join(map(chr, self))

def decode_creature(file, ferror=False):
    """decode a creature located in <file>. if <ferror>, include filename
            in error messages.
       returns (creature_image, creature_data)
       raises IOError if it failes to read the image"""
 
    if file != '-' and not os.path.exists(file):
        err("%r doesn't exist." % file)

    im = Image.open(file if file != '-' else sys.stdin)
    im.load() #force it to actually read the image
    
    if im.size != (128, 128):
        err("invalid creature file %s(should be 128x128, is %dx%d)" % 
                ((fin(file)+' ' if ferror else "",) + im.size))
    
    l = []
    for y in xrange(128):
        for x in xrange(128):
            (r,g,b,a) = im.getpixel((x,y))
            l.extend((b,g,r,a))
 
    stream = Decoder(l)
    data = stream.get_data()
    length = struct.unpack("<L", data[4:8])[0]
    try:
        inflate = zlib.decompress(data[8:8+length])
    except zlib.error, Argument:
        print Argument
        err("invalid creature file %s(zlib decompression failed)" % 
                (fin(file)+' ' if ferror else ''))
    csum = struct.unpack("<Q", data[12+length:20+length])[0]
    if crc64(data[8:8+length]) != csum:
        alert("warning: invalid crc64   ")
    debug("%4dB -> %5dB (%.1f%%) " % (
            length, len(inflate), 100-float(length)/len(inflate)*100))

    return (im, inflate)

CRC64_Table = (
   0x0000000000000000,0x42F0E1EBA9EA3693,0x85E1C3D753D46D26,0xC711223CFA3E5BB5,
   0x493366450E42ECDF,0x0BC387AEA7A8DA4C,0xCCD2A5925D9681F9,0x8E224479F47CB76A,
   0x9266CC8A1C85D9BE,0xD0962D61B56FEF2D,0x17870F5D4F51B498,0x5577EEB6E6BB820B,
   0xDB55AACF12C73561,0x99A54B24BB2D03F2,0x5EB4691841135847,0x1C4488F3E8F96ED4,
   0x663D78FF90E185EF,0x24CD9914390BB37C,0xE3DCBB28C335E8C9,0xA12C5AC36ADFDE5A,
   0x2F0E1EBA9EA36930,0x6DFEFF5137495FA3,0xAAEFDD6DCD770416,0xE81F3C86649D3285,
   0xF45BB4758C645C51,0xB6AB559E258E6AC2,0x71BA77A2DFB03177,0x334A9649765A07E4,
   0xBD68D2308226B08E,0xFF9833DB2BCC861D,0x388911E7D1F2DDA8,0x7A79F00C7818EB3B,
   0xCC7AF1FF21C30BDE,0x8E8A101488293D4D,0x499B3228721766F8,0x0B6BD3C3DBFD506B,
   0x854997BA2F81E701,0xC7B97651866BD192,0x00A8546D7C558A27,0x4258B586D5BFBCB4,
   0x5E1C3D753D46D260,0x1CECDC9E94ACE4F3,0xDBFDFEA26E92BF46,0x990D1F49C77889D5,
   0x172F5B3033043EBF,0x55DFBADB9AEE082C,0x92CE98E760D05399,0xD03E790CC93A650A,
   0xAA478900B1228E31,0xE8B768EB18C8B8A2,0x2FA64AD7E2F6E317,0x6D56AB3C4B1CD584,
   0xE374EF45BF6062EE,0xA1840EAE168A547D,0x66952C92ECB40FC8,0x2465CD79455E395B,
   0x3821458AADA7578F,0x7AD1A461044D611C,0xBDC0865DFE733AA9,0xFF3067B657990C3A,
   0x711223CFA3E5BB50,0x33E2C2240A0F8DC3,0xF4F3E018F031D676,0xB60301F359DBE0E5,
   0xDA050215EA6C212F,0x98F5E3FE438617BC,0x5FE4C1C2B9B84C09,0x1D14202910527A9A,
   0x93366450E42ECDF0,0xD1C685BB4DC4FB63,0x16D7A787B7FAA0D6,0x5427466C1E109645,
   0x4863CE9FF6E9F891,0x0A932F745F03CE02,0xCD820D48A53D95B7,0x8F72ECA30CD7A324,
   0x0150A8DAF8AB144E,0x43A04931514122DD,0x84B16B0DAB7F7968,0xC6418AE602954FFB,
   0xBC387AEA7A8DA4C0,0xFEC89B01D3679253,0x39D9B93D2959C9E6,0x7B2958D680B3FF75,
   0xF50B1CAF74CF481F,0xB7FBFD44DD257E8C,0x70EADF78271B2539,0x321A3E938EF113AA,
   0x2E5EB66066087D7E,0x6CAE578BCFE24BED,0xABBF75B735DC1058,0xE94F945C9C3626CB,
   0x676DD025684A91A1,0x259D31CEC1A0A732,0xE28C13F23B9EFC87,0xA07CF2199274CA14,
   0x167FF3EACBAF2AF1,0x548F120162451C62,0x939E303D987B47D7,0xD16ED1D631917144,
   0x5F4C95AFC5EDC62E,0x1DBC74446C07F0BD,0xDAAD56789639AB08,0x985DB7933FD39D9B,
   0x84193F60D72AF34F,0xC6E9DE8B7EC0C5DC,0x01F8FCB784FE9E69,0x43081D5C2D14A8FA,
   0xCD2A5925D9681F90,0x8FDAB8CE70822903,0x48CB9AF28ABC72B6,0x0A3B7B1923564425,
   0x70428B155B4EAF1E,0x32B26AFEF2A4998D,0xF5A348C2089AC238,0xB753A929A170F4AB,
   0x3971ED50550C43C1,0x7B810CBBFCE67552,0xBC902E8706D82EE7,0xFE60CF6CAF321874,
   0xE224479F47CB76A0,0xA0D4A674EE214033,0x67C58448141F1B86,0x253565A3BDF52D15,
   0xAB1721DA49899A7F,0xE9E7C031E063ACEC,0x2EF6E20D1A5DF759,0x6C0603E6B3B7C1CA,
   0xF6FAE5C07D3274CD,0xB40A042BD4D8425E,0x731B26172EE619EB,0x31EBC7FC870C2F78,
   0xBFC9838573709812,0xFD39626EDA9AAE81,0x3A28405220A4F534,0x78D8A1B9894EC3A7,
   0x649C294A61B7AD73,0x266CC8A1C85D9BE0,0xE17DEA9D3263C055,0xA38D0B769B89F6C6,
   0x2DAF4F0F6FF541AC,0x6F5FAEE4C61F773F,0xA84E8CD83C212C8A,0xEABE6D3395CB1A19,
   0x90C79D3FEDD3F122,0xD2377CD44439C7B1,0x15265EE8BE079C04,0x57D6BF0317EDAA97,
   0xD9F4FB7AE3911DFD,0x9B041A914A7B2B6E,0x5C1538ADB04570DB,0x1EE5D94619AF4648,
   0x02A151B5F156289C,0x4051B05E58BC1E0F,0x87409262A28245BA,0xC5B073890B687329,
   0x4B9237F0FF14C443,0x0962D61B56FEF2D0,0xCE73F427ACC0A965,0x8C8315CC052A9FF6,
   0x3A80143F5CF17F13,0x7870F5D4F51B4980,0xBF61D7E80F251235,0xFD913603A6CF24A6,
   0x73B3727A52B393CC,0x31439391FB59A55F,0xF652B1AD0167FEEA,0xB4A25046A88DC879,
   0xA8E6D8B54074A6AD,0xEA16395EE99E903E,0x2D071B6213A0CB8B,0x6FF7FA89BA4AFD18,
   0xE1D5BEF04E364A72,0xA3255F1BE7DC7CE1,0x64347D271DE22754,0x26C49CCCB40811C7,
   0x5CBD6CC0CC10FAFC,0x1E4D8D2B65FACC6F,0xD95CAF179FC497DA,0x9BAC4EFC362EA149,
   0x158E0A85C2521623,0x577EEB6E6BB820B0,0x906FC95291867B05,0xD29F28B9386C4D96,
   0xCEDBA04AD0952342,0x8C2B41A1797F15D1,0x4B3A639D83414E64,0x09CA82762AAB78F7,
   0x87E8C60FDED7CF9D,0xC51827E4773DF90E,0x020905D88D03A2BB,0x40F9E43324E99428,
   0x2CFFE7D5975E55E2,0x6E0F063E3EB46371,0xA91E2402C48A38C4,0xEBEEC5E96D600E57,
   0x65CC8190991CB93D,0x273C607B30F68FAE,0xE02D4247CAC8D41B,0xA2DDA3AC6322E288,
   0xBE992B5F8BDB8C5C,0xFC69CAB42231BACF,0x3B78E888D80FE17A,0x7988096371E5D7E9,
   0xF7AA4D1A85996083,0xB55AACF12C735610,0x724B8ECDD64D0DA5,0x30BB6F267FA73B36,
   0x4AC29F2A07BFD00D,0x08327EC1AE55E69E,0xCF235CFD546BBD2B,0x8DD3BD16FD818BB8,
   0x03F1F96F09FD3CD2,0x41011884A0170A41,0x86103AB85A2951F4,0xC4E0DB53F3C36767,
   0xD8A453A01B3A09B3,0x9A54B24BB2D03F20,0x5D45907748EE6495,0x1FB5719CE1045206,
   0x919735E51578E56C,0xD367D40EBC92D3FF,0x1476F63246AC884A,0x568617D9EF46BED9,
   0xE085162AB69D5E3C,0xA275F7C11F7768AF,0x6564D5FDE549331A,0x279434164CA30589,
   0xA9B6706FB8DFB2E3,0xEB46918411358470,0x2C57B3B8EB0BDFC5,0x6EA7525342E1E956,
   0x72E3DAA0AA188782,0x30133B4B03F2B111,0xF7021977F9CCEAA4,0xB5F2F89C5026DC37,
   0x3BD0BCE5A45A6B5D,0x79205D0E0DB05DCE,0xBE317F32F78E067B,0xFCC19ED95E6430E8,
   0x86B86ED5267CDBD3,0xC4488F3E8F96ED40,0x0359AD0275A8B6F5,0x41A94CE9DC428066,
   0xCF8B0890283E370C,0x8D7BE97B81D4019F,0x4A6ACB477BEA5A2A,0x089A2AACD2006CB9,
   0x14DEA25F3AF9026D,0x562E43B4931334FE,0x913F6188692D6F4B,0xD3CF8063C0C759D8,
   0x5DEDC41A34BBEEB2,0x1F1D25F19D51D821,0xD80C07CD676F8394,0x9AFCE626CE85B507)

def crc64(data):
    crc = 0xffffffffffffffff
    for byte in data:
        byte = (crc >> 56) ^ ord(byte)
        crc = (crc << 8) & 0xffffffffffffffff ^ CRC64_Table[byte]
    return crc

class Encoder(object):
    def __init__(self, data=0):
        if data:
            self.data = data
        else:
            self.data = [128]*(128*128*4)
        self.hash = 0x811c9dc5
        self.next_pos = 0x0b400
        self.maxsize = 0x00010000
        self.unknown = 0x00000001
        self.mask = 0xfffffff8
        self.invmask = 0x00000007
        self.start_pos = 0x0000b400


    def put_byte(self, byte):
        # again, savagely optimized
        for i in xrange(8):
            bit = (byte >> i) & 1
            
            n = self.next_pos
            d = self.data[n]
            e = (self.hash * 0x1000193) & 0xffffffff 
            self.hash = e ^ ((n&7) | (d&0xf8))
            e = bit ^ ((self.hash & 0x8000) >> 15)
            self.data[n] = (d & 254) | e
            self.next_pos = (n >> 1) ^ (0xb400 & -(n & 1))

    def put_data(self, data):
        for byte in data:
            self.put_byte(ord(byte))

def encode_data(data, im, out):
    comp = zlib.compress(data, 9)
    csum = struct.pack("<Q", crc64(comp))
    odat = "\x16\x0d\x45\x02" + struct.pack("<L", len(comp)) + \
            comp + "\x16\x0d\x45\x02" + csum
    odat = odat.ljust(8192, "\x00")

    if len(odat) > 8192: #This is too large to fit in the image
        err("compressed data is %.1fKB > 8KB, doesn't fit" % 
                (len(odat)/1024.))

    if im:
        if im.size != (128, 128):
            im = im.resize((128,128), resample=Image.ANTIALIAS)
        if im.mode != 'RGBA':
            im = im.convert(mode='RGBA')
        id = im.getdata()
        pix = []
        for x in xrange(128*128):
            r, g, b, a = id[x]
            pix.extend((b, g, r, a))
        enc = Encoder(pix)
    else:
        enc = Encoder()
    enc.put_data(odat)

    im_str = ''.join(chr(enc.data[i+2])+ #BGRA -> RGBA
                     chr(enc.data[i+1])+
                     chr(enc.data[i+0])+
                     chr(enc.data[i+3]) 
                     for i in xrange(0, len(enc.data), 4))

    im = Image.fromstring("RGBA", (128,128), im_str)

    try:
        im.save(out if out != '-' else sys.stdout, "PNG")
    except IOError:
        err("unable to output to %s" % fon(out))

'''Header format:
#    contents   name        description
1    "spore"
2    %04d	    version     version? appears to always be 5
3    %08x	    tid         type id (0x2b978c46 means extracted xml)
4    %08x	    gid         group id  (0x40626200 is the default package)
5    %08x	    id          instance id
6    %08x	    mid         machine id? (constant for a user)
7    %016x	    cid         creature id ((int64)(-1) if offline)
8    %016x	    time        timestamp in seconds since AD 1 (?)
9    %02x	                 length of user name
10   string	    uname       user name
11   %016llx	uid         user id
12   %02x	                 length of creature name
13   string	    name        creature name
14   %03x	                 length of creature description
15   string	    desc        creature description
16   %02x	                 length of creature tags
17   string	    tags        creature tags
18   %02x	                 count of following %08x (unused?)
19   %08x	    trail       repeats for previous count'''

def read_header(data):
    '''Returns a tuple of the length of the header, 
        and a dict of the information in the header of data.
        Raises ValueError if anything fails to parse.'''
    def pop(n):
        d = ret[0][:n]
        ret[0] = ret[0][n:]
        ret[1] += n
        return d
    def pop_int(name, width):
        ret[name] = int(pop(width), 16)
    def pop_str(name, width, mul=1):
        ret[name] = pop(mul * int(pop(width), 16))
    
    ret = {0: data, 1:0} #this is a hack to allow the functions to modify
                         #external non-global state
    if pop(5) != 'spore':
        raise ValueError

    pop_int('version', 4)
    pop_int('tid',     8)
    pop_int('gid',     8)
    pop_int('id',      8)
    pop_int('mid',     8)
    pop_int('cid',    16)

    # Adding the parent
    if ret['version'] == 6:
        pop_int('parent',16)

    pop_int('time',   16)

    pop_str('uname',   2)

    pop_int('uid',    16)

    pop_str('name',    2)
    pop_str('desc',    3)
    pop_str('tags',    2)
    pop_str('trail',   2, 8)

    del ret[0]
    return ret.pop(1), ret

def build_header(head):
    def mask(width):
        return (1<<(8*width)) - 1
    def push_int(name, width, default):
        ret[0] += ("%%0%dx" % width) % (head.get(name, default) & mask(width))
    def push_str(name, width, default, div=1):
        val = head.get(name, default)
        ret[0] += ("%%0%dd" % width) % ((len(val)/div) & mask(width))
        ret[0] += val

    ret = {0:'spore'} # the same hack, for external non-global state

    push_int('version', 4, 5)
    push_int('tid',     8, 0x2b978c46)
    push_int('gid',     8, 0x40626200)
    push_int('id',      8, 0)
    push_int('mid',     8, 0)
    push_int('cid',    16, 0xffffffffffffffff)
    push_int('time',   16, 63349452846)

    push_str('uname',   2, '')

    push_int('uid',    16, 0)

    push_str('name',    2,'')
    push_str('desc',    3, '')
    push_str('tags',    2, '')

    push_str('trail',   2, '', 8)
    return ret[0]


###########################################################################
############ everything past this point is business logic #################
######### not directly involved in the creature file format ###############
###########################################################################

rep_re = re.compile(r'^[-/\w.]*$')

def rep(x):
    if rep_re.match(str(x)):
        return str(x)
    else:
        return repr(x)

def fin(f): #file in name
    return rep(f) if f != '-' else 'stdin'

def fon(f): #file out name
    return rep(f) if f != '-' else 'stdout'


def write_output(file, data):
    try:
        file = open(file, "wb") if file != '-' else sys.stdout
        file.write(data)
        if file != sys.stdout:
            file.close()
    except IOError:
        err("unable to write to %s." % fon(file))

def decode(file, out, opts):
    alert("Decoding from %s to %s   " % 
                (fin(file), fon(out)))

    try:
        creature = decode_creature(file)[1]
        read_header(creature)
    except IOError:
        err("Unable to load image")
    except ValueError:
        alert("warning: malformed creature header")

    write_output(out, creature)    

    alert("\n")

def encode(file, out, opts):
    if opts.image:
        alert("Encoding %s to %s, using image %s   " % 
                (fin(file), fon(out), opts.image))
    else:
        alert("Encoding %s to %s, using a blank image   " % 
                (fin(file), fon(out)))

    try:
        data = (open(file, "rb") if file != '-' else sys.stdin).read()
    except IOError:
        err("unable to read data from %s" % fin(file))
    
    if opts.image:
        try:
            im = Image.open(opts.image)
        except IOError:
            err("unable to load image %s" % rep(opts.image))
    else:
        im = None

    encode_data(data, im, out)

    alert('\n')

def identify(file, out, opts):
    if out != '-':
        alert("Dumping metadata of %s to %s" % (fin(file), rep(out)))

    try:
        creature = decode_creature(file, ferror=True)[1]
    except IOError:
        # try parsing the file as an image
        try:
            f = open(file, "rb") if file != '-' else sys.stdin
            creature = f.read()
            if f != sys.stdin:
                f.close()
  #          if any(ord(c) < 20 for c in creature): #detect ASCII
  #              raise IOError
        except IOError:
            err("unable to load creature from %s" % fin(file))

    try:
        len, h = read_header(creature)
    except ValueError:
        err("malformed creature header in %s" % fin(file))

    try:
        f = open(out, "wb") if out != '-' else sys.stdout

        f.write("""Information about %s:
        Creature Name: %-16s (cid:%#13x, id:  %#10x)
           Created by: %-16s (uid:%#13x, mid: %#10x)
                 Date: %s"""
% (fin(file), h['name'], h['cid'] if h['cid'] != (1<<64)-1 else -1, h['id'],
          h['uname'], h['uid'], h['mid'],time.ctime(y0_to_e(h['time']))))
        if h['desc']:
            f.write("""
          Description: %s""" % h['desc'].strip().replace('\n', ' / '))
        if h['tags']:
            f.write("""
                 Tags: %s""" % h['tags'])
        if f != sys.stdout:
            f.close()
        else:
            f.flush()
    except IOError:
        err("unable to write to %s" % fon(out))

    alert("\n")

def y0_to_e(t):
    #converts seconds since ~year0 to seconds since the epoch
    return t - 62135683200

def e_to_y0(t):
    #inverse
    return t + 62135683200

def quit(msg, status=1):
    if not opts.quiet:
        alert(msg)
    sys.exit(status)

class Error(Exception):
    pass

def err(msg):
    alert("error:", msg, "\n")
    raise Error

def alert(*msgs):
    if not opts.quiet:
        sys.stderr.write(' '.join(str(msg) for msg in msgs))
        sys.stderr.flush()

def debug(*msgs):
    if opts.verbose and not opts.quiet:
        sys.stderr.write(' '.join(str(msg) for msg in msgs))
        sys.stderr.flush()

#########################################################################
#                here there be commandline parsing                      #
#########################################################################

usage = """Spore Creature Compiler %s""" % version + """
  reverse engineering by Ymgve and Rick, frontend by Scaevolus

Usage:  %prog [MODE] [OPTION...] [FILE...]

Examples:
  %prog a.png                      # decode a.png to a.png.xml
  %prog *.png                      # decode creatures in all png images
  %prog -m --name Emu Owl.png      # change creature name in Owl.png to "Emu"
  %prog -e -i b.jpg c.xml -o a.png # encode c.xml in image b.jpg, write to a.png
  %prog -l creature.png            # display name, creator, ... of creature.png

Modes:
  -x, --decode  extract data from FILE (default output:FILE.xml) (default mode)
  -e, --encode  encode data from FILE (default output:FILE.png, image:white)
  -m, --modify  modify information about creature in FILE. (default output:FILE)
  -l, --list    list information about creature in FILE (default output:STDOUT)
"""

def parse_timestamp(option, opt, value):
    try:
        if value.lower() == "now":
            t = time.localtime()
        else:
            strip = re.sub(r'[^\d]', '', value)
            format = "%Y%m%d%H%M%S"[:len(strip)-2]
            t = time.strptime(strip, format) 
        return epoch_to_year0(int(time.mktime(t)))
    except ValueError:
        raise optparse.OptionValueError(
            "option %s: invalid time format: %r" % (value, value))

optparse.Option.TYPES += ("timestamp",) #really, I should subclass and copy
optparse.Option.TYPE_CHECKER["timestamp"] = parse_timestamp #...:effort:

class Formatter(optparse.IndentedHelpFormatter):
    def format_usage(self, usage):
        return usage

class Parser(optparse.OptionParser, object):
    def error(self, msg): #overload so that usage isn't printed on error
        self.exit(2, "%s: error: %s\n" % (self.get_prog_name(), msg))

    def print_help(self, file=sys.stderr):
        super(Parser, self).print_help(file)

parser = Parser(usage=usage, version="%prog " + version,
                formatter=Formatter(max_help_position=30))

s = optparse.SUPPRESS_HELP
p = parser.add_option

#### MODES
p("-x", "--decode", dest="decode", action="store_true", help=s)
p("-e", "--encode", dest="encode", action="store_true", help=s)
p("-m", "--modify", dest="modify", action="store_true", help=s)
p("-l", "--list",   dest="list",   action="store_true", help=s)

### OPTIONS
p("-q", "--quiet", dest="quiet", action="store_true", help="suppress output")
p("-v", "--verbose", dest="verbose", action="store_true", help="verbose output")
p("-s", "--safe", dest="overwrite", action="store_false", default=True,
        help="don't overwrite existing files")
p('-p', '--preserve', dest='preserve', action="store_true",
    help="don't automatically blank creature id and change instance id " +
         "when encoding or modifying")
p('-o', '--output', dest="outfile", help="file to write output to",
        metavar='FILE')
p('-i', '--image', dest='image', help='image to use (will be scaled to 128x128)'
        +' (-e/--encode or -m/--modify only)', metavar='FILE')

### MODIFIERS
m = optparse.OptionGroup(parser, 'Modifiers', '(-m/--modify only)')
p = m.add_option
p('-n', '--name', dest='name', help='set creature name')
p('-d', '--desc', dest='desc', help='set creature description')
p('-t', '--tags', dest='tags', help='set creature tags')
p('-u', '--user', dest='user', help='set creator name')
p('-c', '--date', dest='time', type='timestamp', help='set creation time '+
 '(format: either "now" or yyyy[mm[dd[HH[MM[SS]]]]], non-digits are ignored)')
p('--cid', dest='cid', help='set creature id (-1 is null)', type="int")
p('--id',  dest= 'id', help='set instance id', type="int")
p('--uid', dest='uid', help='set creator id',  type="int")
p('--mid', dest='mid', help='set machine id',  type="int")
parser.add_option_group(m)

opts, args = parser.parse_args()

if len(args) == 0:
    if len(sys.argv) > 1:
        parser.error("At least one file must be specified")
    parser.print_help()
    exit(1)

if sum(1 for x in (opts.decode, opts.encode, opts.modify, opts.list) if x) > 1:
    parser.error("more than one mode specified")
mode = ("encode" if opts.encode else "modify" if opts.modify else
        "list" if opts.list else "decode") #decode is the default

if mode != "modify" and [opts.name, opts.desc, opts.tags, opts.user, opts.time,
                opts.cid, opts.id, opts.uid, opts.mid].count(None) != 9:
    parser.error("modifiers are only valid in modify mode (-m/--modify)")

if mode != "encode" and opts.image:
    parser.error("image is only valid in encode mode (-e/--encode)")

del parse_timestamp, Formatter, Parser, parser, s, p #cleanup

mode_func = {'decode': decode, 'list': identify, 'encode': encode}[mode]
mode_formats = {'decode': '%(s)s.xml', 'list': '-', 'encode': '%(s)s.png'}

def get_outfile(infile, outfile):
    if not outfile:
        o = mode_formats[mode] % {'s':infile}
    else:
        o = outfile
    if o != '-' and os.path.exists(o) and not opts.overwrite:
        err("%s exists, not overwriting" % rep(out))
    return o

argn = len(args)
argw = len(str(argn))

for num, file in enumerate(args):
    sys.stdout.flush()
    sys.stderr.flush()
    if argn > 1:
        alert(("[%%%dd/%d] " % (argw, argn)) % (num + 1))
    try:
        mode_func(file, get_outfile(file, opts.outfile), opts)
    except Error:
        pass
    except KeyboardInterrupt:
        alert("\ninterrupt!\n")
        sys.exit(3)
