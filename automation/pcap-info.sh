#!/usr/bin/env python3
# -*- coding: utf-8 eval: (yapf-mode 1) -*-
#
# Copyright (c) 2020 LabN Consulting, L.L.C.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from autovpp import log
import argparse
import gzip
import io
import logging
import sys
import struct
import binascii


def decode_utf8(o):
    return o.decode("utf-8")


def decode_bin(o):
    return binascii.hexlify(o)


SBH_BIG_ENDIAN_MAGIC = b"\x1A\x2B\x3C\x4D"
SBH_LITTLE_ENDIAN_MAGIC = b"\x4D\x3C\x2B\x1A"
SBH_LEN_EOF = 0xFFFFFFFFFFFFFFFF

BT_SECTION_HEADER = 0x0A0D0D0A
BT_IF_DESC = 1
BT_SIMPLE_PACKET = 3
BT_NAME_RESOLUTION = 4
BT_IF_STAT = 5
BT_PACKET = 6

BLOCK_TYPE_NAME = {
    BT_SECTION_HEADER: "Section Header Block",
    BT_IF_DESC: "Interface Description Block",
    BT_SIMPLE_PACKET: "Simple Packet Block",
    BT_NAME_RESOLUTION: "Name Resolution Block",
    BT_IF_STAT: "Interface Statistics Block",
    BT_PACKET: "Enhanced Packet Block",
}

OPT_ENDOFOPT = 0
OPT_COMMENT = 1
OPT_CUSTOM_TRANS_UTF8 = 2988
OPT_CUSTOM_TRANS_BIN = 2989
OPT_CUSTOM_NON_TRANS_UTF8 = 19372
OPT_CUSTOM_NON_TRANS_BIN = 19373

OPT_NAME = {
    OPT_ENDOFOPT: "OPT_ENDOFOPT",
    OPT_COMMENT: "OPT_COMMENT",
    OPT_CUSTOM_TRANS_UTF8: "OPT_CUSTOM_TRANS_UTF8",
    OPT_CUSTOM_TRANS_BIN: "OPT_CUSTOM_TRANS_BIN",
    OPT_CUSTOM_NON_TRANS_UTF8: "OPT_CUSTOM_NON_TRANS_UTF8",
    OPT_CUSTOM_NON_TRANS_BIN: "OPT_CUSTOM_NON_TRANS_BIN",
}

OPT_DECODE = {
    OPT_COMMENT: decode_utf8,
    OPT_CUSTOM_TRANS_UTF8: decode_utf8,
    OPT_CUSTOM_TRANS_BIN: decode_bin,
    OPT_CUSTOM_NON_TRANS_UTF8: decode_utf8,
    OPT_CUSTOM_NON_TRANS_BIN: decode_bin,
}

SHB_HARDWARE = 2
SHB_OS = 3
SHB_USERAPPL = 4

SHB_OPT_NAME = {
    SHB_HARDWARE: "SHB_HARDWARE",
    SHB_OS: "SHB_OS",
    SHB_USERAPPL: "SHB_USERAPPL",
}

SHB_OPT_DECODE = {
    SHB_HARDWARE: decode_utf8,
    SHB_OS: decode_utf8,
    SHB_USERAPPL: decode_utf8,
}

IF_NAME = 2
IF_DESCRIPTION = 3
IF_IPV4ADDR = 4
IF_IPV6ADDR = 5
IF_MACADDR = 6
IF_EUIADDR = 7
IF_SPEED = 8
IF_TSRESOL = 9
IF_TZONE = 10
IF_FILTER = 11
IF_OS = 12
IF_FCSLEN = 13
IF_TSOFFSET = 14

IDB_OPT_NAME = {
    IF_NAME: "IF_NAME",
    IF_DESCRIPTION: "IF_DESCRIPTION",
    IF_IPV4ADDR: "IF_IPV4ADDR",
    IF_IPV6ADDR: "IF_IPV6ADDR",
    IF_MACADDR: "IF_MACADDR",
    IF_EUIADDR: "IF_EUIADDR",
    IF_SPEED: "IF_SPEED",
    IF_TSRESOL: "IF_TSRESOL",
    IF_TZONE: "IF_TZONE",
    IF_FILTER: "IF_FILTER",
    IF_OS: "IF_OS",
    IF_FCSLEN: "IF_FCSLEN",
    IF_TSOFFSET: "IF_TSOFFSET",
}

IDB_OPT_DECODE = {
    IF_NAME: decode_utf8,
    IF_DESCRIPTION: decode_utf8,
    # IF_IPV4ADDR: 8,
    # IF_IPV6ADDR: 17,
    # IF_MACADDR: 6,
    # IF_EUIADDR: 8,
    IF_SPEED: "Q",
    IF_TSRESOL: "B",
    IF_TZONE: "I",
    # IF_FILTER: decode_filter,
    IF_OS: decode_utf8,
    IF_FCSLEN: "B",
    IF_TSOFFSET: "Q",
}

ISB_STARTTIME = 2
ISB_ENDTIME = 3
ISB_IFRECV = 4
ISB_IFDROP = 5
ISB_FILTERACCEPT = 6
ISB_OSDROP = 7
ISB_USRDELIV = 8

ISB_OPT_NAME = {
    ISB_STARTTIME: "ISB_STARTTIME",
    ISB_ENDTIME: "ISB_ENDTIME",
    ISB_IFRECV: "ISB_IFRECV",
    ISB_IFDROP: "ISB_IFDROP",
    ISB_FILTERACCEPT: "ISB_FILTERACCEPT",
    ISB_OSDROP: "ISB_OSDROP",
    ISB_USRDELIV: "ISB_USRDELIV",
}

ISB_OPT_DECODE = {
    ISB_STARTTIME: "Q",
    ISB_ENDTIME: "Q",
    ISB_IFRECV: "Q",
    ISB_IFDROP: "Q",
    ISB_FILTERACCEPT: "Q",
    ISB_OSDROP: "Q",
    ISB_USRDELIV: "Q",
}


def is_common_opt(ocode):
    return ocode in OPT_NAME


def is_isb_opt(ocode):
    return ocode in ISB_OPT_NAME


def get_type_name(btype):
    return BLOCK_TYPE_NAME[btype] if btype in BLOCK_TYPE_NAME else f"0x{btype:08x}"


OPT_NAMES = {
    BT_SECTION_HEADER: SHB_OPT_NAME,
    BT_IF_DESC: IDB_OPT_NAME,
    BT_IF_STAT: ISB_OPT_NAME,
}


def get_opt_name(btype, ocode):
    names = OPT_NAMES[btype] if btype in OPT_NAMES else OPT_NAME
    if ocode in names:
        return names[ocode]
    elif ocode in OPT_NAME:
        return OPT_NAME[ocode]
    return f"0x{ocode:04x}"


def _get_opt_value(code, decoders, o):
    if not len(o):
        return ""
    if code in decoders:
        decoder = decoders[code]
    elif code in OPT_DECODE:
        decoder = OPT_DECODE[code]
    else:
        return binascii.hexlify(o)

    if hasattr(decoder, "__call__"):
        return decoder(o)
    else:
        return struct.unpack(decoder, o)[0]


OPT_DECODERS = {
    BT_SECTION_HEADER: SHB_OPT_DECODE,
    BT_IF_DESC: IDB_OPT_DECODE,
    BT_IF_STAT: ISB_OPT_DECODE,
}


def get_opt_value(btype, ocode, o):
    decoders = OPT_DECODERS[btype] if btype in OPT_DECODERS else OPT_DECODE
    return _get_opt_value(ocode, decoders, o)


def block_iter(fobj):
    bdata = fobj.read(8)
    if not bdata:
        return
    btype, blen = struct.unpack("II", bdata)
    bdata += fobj.read(blen - 8)
    blen2 = struct.unpack("I", bdata[-4:])[0]
    assert blen == blen2
    yield btype, bdata[:-4]


def rev_block_iter(fobj, stopat=0):
    # Seek back for the length
    while fobj.seek(0, io.SEEK_CUR) != stopat:
        pos = fobj.seek(-4, io.SEEK_CUR)
        bdata = fobj.read(4)
        if not bdata:
            return None, None
        blen = struct.unpack("I", bdata)[0]
        fobj.seek(-blen, io.SEEK_CUR)

        # Read and then seek back to start
        bdata = fobj.read(blen)
        fobj.seek(-blen, io.SEEK_CUR)

        btype, blen2 = struct.unpack("II", bdata[0:8])
        assert blen2 == blen
        yield btype, bdata[8:-4]


def opt_iter(opts):
    while opts:
        ocode, olen = struct.unpack("HH", opts[:4])
        opts = opts[4:]
        if ocode != 0 and olen == 0:
            paddedlen = 4
        else:
            paddedlen = (olen + 3) & ~0x3
        odata = opts[:olen]
        opts = opts[paddedlen:]
        yield ocode, odata


def parse_block(btype, b):
    bname = get_type_name(btype)

    assert btype != BT_SECTION_HEADER
    if btype == BT_IF_STAT:
        ifid = struct.unpack("I", b[:4])
        timestamp = struct.unpack("Q", b[4:12])
        opts = b[12:]
        logging.info("%s", f"IF_STAT_BLOCK: ifid: {ifid} ts: {timestamp}")
        for ocode, o in opt_iter(opts):
            optname = get_opt_name(btype, ocode)
            optval = get_opt_value(btype, ocode, o)
            logging.info("%s", f"OPT: {optname}: {optval}")
    elif btype == BT_IF_DESC:
        linktype = struct.unpack("H", b[:2])
        snaplen = struct.unpack("I", b[4:8])
        opts = b[8:]
        logging.info("%s", f"IF_DESC_BLOCK: linktype: {linktype} snaplen: {snaplen}")
        for ocode, o in opt_iter(opts):
            optname = get_opt_name(btype, ocode)
            optval = get_opt_value(btype, ocode, o)
            logging.info("%s", f"OPT: {optname}: {optval}")
    else:
        logging.info("%s", f"BLOCK: type: {bname} length: {len(b)}")


def parse_section(pf, b, isgzip=False):
    btype, _, magic = struct.unpack("II4s", b[0:12])
    assert btype == BT_SECTION_HEADER
    assert magic == SBH_LITTLE_ENDIAN_MAGIC

    major, minor = struct.unpack("HH", b[12:16])
    seclen = struct.unpack("Q", b[16:24])[0]
    opts = b[24:]

    logging.info("%s", f"SECHDR: V: {major}.{minor} sec-len {seclen}")

    for ocode, o in opt_iter(b[24:]):
        optname = get_opt_name(btype, ocode)
        optval = get_opt_value(btype, ocode, o)
        logging.info("%s", f"OPT: {optname}: {optval}")

    # Get the IF Descriptor block

    if isgzip:
        if seclen == SBH_LEN_EOF:
            secdata = pf.read()
        else:
            secdata = pf.read(seclen)
        pfsecend = pf.seek(0, io.SEEK_CUR)

        sf = io.BytesIO(secdata)
        secstart = 0
        secend = len(secdata)
    else:
        secstart = pf.seek(0, io.SEEK_CUR)
        if seclen == SBH_LEN_EOF:
            pfsecend = pf.seek(0, io.SEEK_END)
            secstart = pf.seek(secstart, io.SEEK_SET)
        else:
            pfsecend = secstart + seclen
        secend = pfsecend
        sf = pf

    if False:
        # If we want to search for it
        pass
    else:
        # Or just assume it's the first block if preesnt
        btype, b = next(block_iter(sf))
        if btype == BT_IF_DESC:
            parse_block(btype, b)

    # Reset to the end
    sf.seek(secend, io.SEEK_SET)

    if False:
        # If we want to search for it
        for btype, b in rev_block_iter(sf, secstart):
            parse_block(btype, b)
    else:
        # Or just assume it's the last block if preesnt
        btype, b = next(rev_block_iter(sf, secstart))
        if btype == BT_IF_STAT:
            parse_block(btype, b)

    # Return to the end of the section.
    if sf == pf:
        pf.seek(pfsecend, io.SEEK_SET)


def main(*margs):
    parser = argparse.ArgumentParser()
    parser.add_argument("pcapfile", help="pcap file to get drops from")
    args = parser.parse_args(*margs)

    log.init_util(args)

    # Open in binary mode.
    if args.pcapfile.endswith(".gz"):
        pf = gzip.open(args.pcapfile, "rb")
        isgzip = True
    else:
        pf = open(args.pcapfile, "rb")
        isgzip = False

    for btype, b in block_iter(pf):
        parse_section(pf, b, isgzip)


if __name__ == "__main__":
    try:
        main()
    except Exception as ex:
        logging.error("Got Exception in main: %s", str(ex))
        from traceback import print_exc
        print_exc()
        sys.exit(0)
