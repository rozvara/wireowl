#!/usr/bin/env python3
# -*- coding: utf8 -*-

# `wireowl` shows statistics and visualisation of network activity in interactive
# terminal app, either live from network interface or from saved capture.
#
# This file is part of wireowl which is released under GNU GPLv2 license.
#
# Copyright 2021, 2022 Jiri Rozvaril <rozvara at vync dot org>

import os
import stat
import argparse
from datetime import datetime
from wireowl_tui import run_ui
from wireowl_backend import TrafficInspector, PacketReader


def check_file_type(pathname):
    try:
        if stat.S_ISFIFO(os.stat(pathname).st_mode):
            return 'pipe'
        if os.path.isfile(pathname):
            return 'file'
    except:
        pass
    return None


def main():
    parser = argparse.ArgumentParser(description= \
        """Shows devices in network traffic and statistics of their connections.
        Input file must be in a tab-delimited format exported from tshark(1).
        It could be already exported .csv file or .pcap/realtime capture
        with tshark's stdout redirected into a named pipe.
        If you have no .csv file ready, run shell script 'wireowl' instead.""")

    parser.add_argument(dest='filename', metavar='PATHNAME', type=str,
        help="path name of tab delimited text file or named pipe")

    parser.add_argument('-s', '--speed', dest='speed', metavar='SPEED',
        type=int, default=0,
        help="""replay speed of traffic recorded in .pcap/.csv file,
        eg. 60 means 60x faster (1sec=1min), 1 means "realtime",
        0 or no parameter means processing at maximal computing speed.""")

    parser.add_argument('-l', '--limit', dest='limit', metavar='PACKETS',
        type=int, default=float('inf'),
        help="maximum number of packets to process")

    parser.add_argument('-p', '--preserve', dest='preserve_data', action='store_true',
        help="keeps network packets data in a tab delimited text file located in /tmp folder.")

    args = parser.parse_args()

    if not check_file_type(args.filename):
        print(f"\nError: file/pipe '{args.filename}' not found.\n")
        quit()

    if args.preserve_data:
        out_file = '/tmp/wireowl-' + datetime.now().strftime('%Y%m%d-%H%M%S-%f') + '.csv'
    else:
        out_file = None

    worker = TrafficInspector()
    reader = PacketReader(args.filename, worker, args.speed, args.limit, out_file)

    reader.start()
    run_ui(worker, reader)
    reader.stop()

    status = reader.get_statuses()
    if status['err']:
        print("Packet reader error: ", end='')
        if status['err'] < 10:
            print("not a tab delimited format/wrong number of columns/wrong columns order.")
        elif status['err'] > 10:
            print(f"could not write to output file {out_file}.")


if __name__ == '__main__':
    main()
