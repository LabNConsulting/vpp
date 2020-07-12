#!/usr/bin/env python
# -*- coding: utf-8 eval: (yapf-mode 1) -*-
#
# June 22 2020, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2020, LabN Consulting, L.L.C
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
import argparse
import collections
import io
import logging
import struct
import sys

import autovpp.log

FILE_HEADER_FMT = ">BBHI"
FILE_LITTLE_ENDIAN_MASK = 0x80
FILE_VERSION = 0x01
FILE_VERSION_MASK = 0x7F

ST_STRINGS = 1
ST_SYMBOLS = 2
ST_EVENT_DEFS = 3
ST_TRACK_DEFS = 4
ST_EVENTS = 5

ST_NAME = {
    ST_STRINGS: "ST_STRINGS",
    ST_SYMBOLS: "ST_SYMBOLS",
    ST_EVENT_DEFS: "ST_EVENT_DEFS",
    ST_TRACK_DEFS: "ST_TRACK_DEFS",
    ST_EVENTS: "ST_EVENTS",
}

SECTION_HEADER_FMT = ">II"
SYMBOL_SECTION_HEADER_FMT = ">64sI"
EVENT_DEFINITION_SECTION_HEADER_FMT = ">64sI"
TRACK_DEFINITION_SECTION_HEADER_FMT = ">64sI"
EVENT_SECTION_HEADER_FMT = ">64sII"

SYMBOL_ENTRY_FMT = ">II"
EVENT_DEFINITION_FMT = ">III"
TRACK_DEFINITION_FMT = ">II"
EVENT_ENTRY_FMT = ">QIII"


class BoundEvent:
    event_code: int
    event_name: str
    datum_name: str


class BoundTrack:
    track_code: int
    track_name: str


import pdb
g_stringbuf = {}
g_strings_hashed = {}
g_event_defs = {}
g_event_def_codes = {}
g_track_defs = {}
g_track_def_codes = {}
g_events = {}
g_events_ts = []


def zindex(mv):
    for i, v in enumerate(mv):
        if v == 0:
            return i
    raise Exception("No NIL byte found")


def zsview(mv):
    "Return a memoryview slice for a NUL temrinated string"
    return mv[:zindex(mv)]


def decode_strings(secdata):
    table_name = zsview(secdata)
    table_name_dec = table_name.tobytes().decode('ascii')
    logging.debug(f"DECODE string section: {table_name_dec}")

    assert table_name not in g_stringbuf
    g_stringbuf[table_name] = secdata
    g_strings_hashed[table_name] = {}
    g_strings_hashed[table_name][0] = table_name


def get_string(ht, offset):
    if offset not in ht:
        data = g_stringbuf[ht[0]][offset:]
        ht[offset] = zsview(data).tobytes()
    return ht[offset]


def elt_iter(data, fmt):
    fmtlen = struct.calcsize(fmt)
    end = len(data)
    offset = 0
    while offset < end:
        eltdata = struct.unpack_from(fmt, data, offset)
        offset += fmtlen
        yield eltdata


def decode_symbols(secdata, stable, nsyms):
    stable = zsview(stable)
    ht = g_strings_hashed[stable]
    logging.debug(f"DECODE symbols section: stable: {stable} nsyms: {nsyms}")
    for sym, nameoff in elt_iter(secdata, SYMBOL_ENTRY_FMT):
        symname = get_string(ht, nameoff)
        logging.debug(f"DECODE symbol: symbol: {symname} value: 0x{sym:x}")


def decode_event_defs(secdata, stable, ndefs):
    stable = zsview(stable)
    ht = g_strings_hashed[stable]
    logging.debug(f"DECODE event defs section: stable: {stable} ndefs: {ndefs}")
    for code, eoff, doff in elt_iter(secdata, EVENT_DEFINITION_FMT):
        efmt = get_string(ht, eoff)
        dfmt = get_string(ht, doff)
        logging.debug(f"DECODE event def: code: 0x{code:x} efmt: {efmt} dfmt: {dfmt}")
        if dfmt != b"%s":
            pdb.set_trace()
        assert dfmt == b"%s"
        g_event_defs[code] = efmt
        g_event_def_codes[efmt] = code
        g_events[code] = list()


def decode_track_defs(secdata, stable, ndefs):
    stable = zsview(stable)
    ht = g_strings_hashed[stable]
    logging.debug(f"DECODE track defs section: stable: {stable} ndefs: {ndefs}")
    for code, toff in elt_iter(secdata, TRACK_DEFINITION_FMT):
        tfmt = get_string(ht, toff)
        logging.debug(f"DECODE track def: code: 0x{code:x} tfmt: {tfmt}")
        g_track_defs[code] = tfmt
        g_track_def_codes[tfmt] = code


def decode_events(secdata, stable, nev, cpms, tfilter, efilter):
    stable = zsview(stable)
    ht = g_strings_hashed[stable]
    logging.debug(f"DECODE events section: stable: {stable} nevents: {nev} clks-per-ms: {cpms}")

    count = 0
    istty = sys.stdin.isatty()

    for timestamp, track, code, datum in elt_iter(secdata, EVENT_ENTRY_FMT):
        # logging.debug(
        #     f"DECODE event: track: 0x{track:x} code 0x{code:x} datum: {datum:x} dstr: {dstr} ts: {timestamp}"
        # )
        if tfilter and track != tfilter:
            continue
        if efilter and code != efilter:
            continue
        g_events[code].append((timestamp, track, datum, ht))
        g_events_ts.append((timestamp, code, track, datum, ht))

        if istty and (count & 0x2FF) == 0:
            print(f"Events: {count}\r", file=sys.stderr)
        count += 1

    print(f"Events: {count}\n", file=sys.stderr)


SEC_DECODERS = {
    ST_STRINGS: decode_strings,
    ST_SYMBOLS: decode_symbols,
    ST_EVENT_DEFS: decode_event_defs,
    ST_TRACK_DEFS: decode_track_defs,
    ST_EVENTS: decode_events,
}

# Not currently used -- strings section has no format.
SEC_HEADER_UNPACK = {
    ST_SYMBOLS: SYMBOL_SECTION_HEADER_FMT,
    ST_EVENT_DEFS: EVENT_DEFINITION_SECTION_HEADER_FMT,
    ST_TRACK_DEFS: TRACK_DEFINITION_SECTION_HEADER_FMT,
    ST_EVENTS: EVENT_SECTION_HEADER_FMT,
}


def section_iter(fobj):
    sechdrlen = struct.calcsize(SECTION_HEADER_FMT)
    while True:
        data = fobj.read(sechdrlen)
        if len(data) == 0:
            return
        sectype, seclen = struct.unpack(SECTION_HEADER_FMT, data)
        assert sectype in SEC_DECODERS
        yield sectype, seclen


def read_cpel(fobj, skip_events=False, filters=None):
    filehdrlen = struct.calcsize(FILE_HEADER_FMT)
    filehdrdata = fobj.read(filehdrlen)
    version, _, nsections, file_date = struct.unpack(FILE_HEADER_FMT, filehdrdata)

    if version != FILE_VERSION:
        if version & FILE_LITTLE_ENDIAN_MASK:
            print("Little endian data format not supported")
            sys.exit(1)
        print(f"Unsupported file version 0x{version:x}")
        sys.exit(1)

    def call_decoder(fobj, sectype, seclen, filters):
        secdata = fobj.read(seclen)
        mv = memoryview(secdata)
        if sectype not in SEC_HEADER_UNPACK:
            SEC_DECODERS[sectype](mv)
        else:
            fmt = SEC_HEADER_UNPACK[sectype]
            hlen = struct.calcsize(fmt)
            # XXX we should use a memory buffer here to avoid copy
            if filters:
                SEC_DECODERS[sectype](mv[hlen:], *struct.unpack_from(fmt, mv, 0), *filters)
            else:
                SEC_DECODERS[sectype](mv[hlen:], *struct.unpack_from(fmt, mv, 0))

    # First pass we skip events
    for sectype, seclen in section_iter(fobj):
        if sectype == ST_EVENTS:
            fobj.seek(seclen, io.SEEK_CUR)
        else:
            call_decoder(fobj, sectype, seclen, None)

    print(f"track-defs: {len(g_track_defs)} event-defs: {len(g_event_defs)}", file=sys.stderr)

    if skip_events:
        return

    # Reset to start of file.
    fobj.seek(filehdrlen, io.SEEK_SET)

    # Second pass we skip all *but* events
    for sectype, seclen in section_iter(fobj):
        if sectype != ST_EVENTS:
            fobj.seek(seclen, io.SEEK_CUR)
        else:
            call_decoder(fobj, sectype, seclen, filters)


def and_next_iter(l):
    it = iter(l)
    c = next(it)
    for n in it:
        yield c, n
        c = n


def event_fence_iter(evlist, evcode):
    it = iter(evlist)
    fenced = []
    for c in it:
        if c[1] == evcode:
            fenced.append(c)
            break
    else:
        return

    for n in it:
        if n[1] == evcode:
            fenced.append(n)
            yield fenced
            fenced = [n]
        else:
            fenced.append(n)


def event_fence_delta_avg_iter(evlist, runavg_code, runavg_len):
    ring = collections.deque(maxlen=runavg_len)

    it = event_fence_iter(evlist, runavg_code)
    delta = 0
    p = 0
    fenced = []
    for fenced in it:
        # clock of newest - clock of oldest
        delta = fenced[-1][0] - fenced[0][0]
        ring.append(delta)
        p += delta
        if len(ring) == runavg_len:
            break
    else:
        return

    mean = p / runavg_len
    yield fenced, delta, mean

    for fenced in it:
        # clock of newest - clock of oldest
        delta = fenced[-1][0] - fenced[0][0]
        oldest = ring.pop()
        ring.append(delta)
        mean = mean + (delta - oldest) / runavg_len
        yield fenced, delta, mean


def main(*margs):
    parser = argparse.ArgumentParser()
    parser.add_argument("evfile", help="CPEL format event file")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--list-defs", action="store_true")
    parser.add_argument("--track-filter", type=int, help="Display only given track code")
    parser.add_argument("--event-filter", type=int, help="Display only given event code")
    parser.add_argument("--mean-event",
                        type=int,
                        help="Start displaying events with given id/clock")
    parser.add_argument("--deltas",
                        action="store_true",
                        help="Display timestamp deltas for filtered event")
    args = parser.parse_args(*margs)

    autovpp.log.init_util(args)

    if args.track_filter or args.event_filter:
        filters = (args.track_filter, args.event_filter)
    else:
        filters = (None, None)

    read_cpel(open(args.evfile, "rb"), skip_events=args.list_defs, filters=filters)

    if args.list_defs:
        for code in sorted(g_track_defs):
            print(f"TRACK\t{code}\t{g_track_defs[code]}")

        for code in sorted(g_event_defs):
            print(f"EVDEF\t{code}\t{g_event_defs[code]}")
        return

    # Get an iterator we can use over and over.
    if args.mean_event:
        for fenced, delta, mean in event_fence_delta_avg_iter(g_events_ts, args.mean_event, 100):
            # We should probably allow for stdev or something.
            pct = .25
            meandiff = mean * pct
            if delta > (mean + meandiff) or delta < (mean - meandiff):
                print(f"Found large delta {delta} from mean {mean}")
                off = fenced[0][0]
                for e in fenced:
                    td = e[0] - off
                    es = get_string(e[4], e[3])
                    tds = f"{e[2]}:{g_track_defs[e[2]]}"
                    eds = f"{e[1]}:{g_event_defs[e[1]]}"
                    print(f"+{td}\t{tds}\t{eds}\t{es}")
                print("----")
    elif args.deltas:
        assert args.event_filter
        code = args.event_filter
        for e, ne in and_next_iter(g_events[code]):
            delta = ne[0] - e[0]
            print(f"{code}\t{ne[0]}\t{ne[1]}\t{ne[2]}\t{delta}")
    else:
        for code in g_events:
            elist = g_events[code]
            for ev in elist:
                s = get_string(ev[3], ev[2])
                #import pdb
                #pdb.set_trace()
                print(f"{code}\t{ev[0]}\t{ev[1]}\t{ev[2]}\t{s}")


if __name__ == "__main__":
    try:
        main()
    except Exception as ex:
        from traceback import format_exc
        logging.error("Got Exception in main: %s\n%s", str(ex), format_exc())
        sys.exit(1)
