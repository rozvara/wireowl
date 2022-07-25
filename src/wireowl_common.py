# -*- coding: utf8 -*-

# This file is part of wireowl and pcap2pdf which are released under GNU GPLv2 license.
#
# Copyright 2021, 2022 Jiri Rozvaril <rozvara at vync dot org>

import time

# time duration in various formats
#
def rel_time(epoch, variant=1):
    # 1: 7 chars '23h 12s' or  '*******' plus negative sign
    # 2: any length, eg. 387d 23h 15m 30s
    if epoch < 0:
        epoch = -int(epoch)
        ret = '-'  # negative sign
    else:
        epoch = int(epoch)
        ret = ''
    d = int(epoch / 86400); epoch = epoch % 86400
    h = int(epoch / 3600);  epoch = epoch % 3600
    m = int(epoch / 60)
    s  = epoch % 60
    if variant == 1 and d > 99:
        ret = '*'*7
    elif d > 0:
        ret += f"{d}d {h}h {m}m {s}s"
    elif h > 0:
        ret += f"{h}h {m}m {s}s"
    elif m > 0:
        ret += f"{m}m {s}s"
    else:
        ret += f"{s}s"
    if variant == 1:
        parts = ret.split(' ')
        ret = ' '.join(parts[:2])
    return ret


# various time formats
#
def fmt_time(epoch, variant=1):
    # 1:  17:55:31
    # 2:  24.05.2021 17:55:31
    st = time.gmtime(epoch)
    if variant == 1:
        ret = time.strftime("%H:%M:%S", st)
    else:
        # TODO (not used now, but l10n)
        ret = time.strftime("%d.%m.%Y %H:%M:%S", st)
    return ret

