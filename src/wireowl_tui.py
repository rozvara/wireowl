# -*- coding: utf8 -*-

# This file is part of wireowl which is released under GNU GPLv2 license.
#
# Copyright 2021, 2022 Jiri Rozvaril <rozvara at vync dot org>

# TODOs
# - fix/clear todos
# - more sort options
# - persistent settings
# - kiosk mode

import curses
import time
from datetime import date
from wireowl_common import rel_time, fmt_time

VERSION="0.4.3"

# UI CONST
HIGHLIGHTTIME = -5  # seconds to highlight active communication (negative value, as to the past)

# colors
_, NORMAL, TOPBAR, TABHIGH, TABDIM, GLOBALDOMAIN, LOCALNETWORK, \
ACTIVEIP, ACTIVEDEVICE, ACTIVERX, ACTIVETX, \
CONNECTOR, ALERTDOMAIN, CLIENTMARK, MENUKEY, MENUTITLE = range(16)

# some layout constants
RP, GR = range(2)
curses_MOUSE_WHEEL_DOWN = 2097152
curses_MOUSE_WHEEL_UP = curses.BUTTON4_PRESSED
MOUSEMASK = curses.BUTTON1_CLICKED \
            + curses_MOUSE_WHEEL_DOWN \
            + curses_MOUSE_WHEEL_UP

# key_label, mouse_click_key, switch_type, label_false, label_true
MENU = [['F1',  curses.KEY_F1,  None, 'Help'],
        ['F3',  curses.KEY_F3,  'h',  'Hi Off',  'Hi On '],
        ['F4',  curses.KEY_F4,  'd',  'Clients', 'Devices'],
        ['F5',  curses.KEY_F5,  'l',  'List  ',  'Detail'],
        ['F6',  curses.KEY_F6,  's',  'Chrono',  'Active'],
        ['F8',  curses.KEY_F8,  None, 'Clear'],
        ['F10', curses.KEY_F10, None, 'Quit']]


# app state singleton
#
class UI():
    def __init__(self):
        self.show_debug = False     # show debug info

        # UI DEFAULT VALUES
        self.highlight = True       # highlight active connections
        self.all_devices = True     # show all devices(T) or filter to clients only(F)
        self.detail = True          # detail(T) or list of devices(F)
        self.show_more = None       # type of additional details shown (or None)
        self.active_first = True    # sort by activity(T) or chronologically(F)
        self.show_local = True      # show/hide local network devices
        self.show_tx_graph = True   # show/hide graph of traffic sent
        self.show_rx_graph = False  # show/hide graph of traffic received
        self.show_ip_stat = True    # show/hide IP statistics in list
        self.show_cnames = False    # show/hide CNAME records for domains
        self.sec_graph = True       # show graph in seconds(T) or minutes(F)
        self.abs_time = True        # absolute(T) or relative time(F)
        self.dark_theme = True      # dark(T) or light theme(F)

        self.is_kiosk = False       # kiosk mode w/ auto switch to new client

        # curses/content
        self.scr = None             # curses screen object
        self.content = []           # rows with content
        self.w = self.h = 0         # current terminal size
        self.reserved_top = 0       # rows above content
        self.neth = 0               # net rows for content
        self.scroll = 0             # position of scrolling up/down
        self.refresh = 10           # screen refresh in 1/10s
        self.key = curses.ERR       # last key pressed
        self.running = True         # quit app when false
        self.debug = ''             # development helper
        # app vars
        self.statuses = None        # statuses from packet reader
        self.devices = []           # all devices
        self.clients = []           # all clients (sublist to devices)
        self.devmenu = []           # devices as menu items
        self.selected = None        # selected device
        self.device = None          # details/stats of selected device
        self.conns = None           # connections of selected device

        self.timezone_correction = time.timezone - 3600*time.localtime().tm_isdst

    def rows(self):
        return len(self.content)

    def set_layout(self, t, b):
        self.reserved_top = t
        self.neth = self.h - t - b



#    #          ###
 #    #          #  #    # # #####
  #    #         #  ##   # #   #
   #    #        #  # #  # #   #
  #    #         #  #  # # #   #
 #    #          #  #   ## #   #
#    #          ### #    # #   #


# main entry point - curses wrapper for curses app
#
def run_ui(worker_thread, reader_thread, kiosk_mode=False, exp_time=None):
    global ui, backend, reader

    ui = UI()
    if kiosk_mode:
        ui.is_kiosk = True
        ui.all_devices = False # clients
        ui.show_local = False

    backend = worker_thread
    reader = reader_thread
    curses.wrapper(main_app_loop)


# set colors
#
def set_curses_colors():
    if ui.dark_theme:
        curses.init_pair(NORMAL, curses.COLOR_WHITE, curses.COLOR_BLACK)
        curses.init_pair(TOPBAR, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(TABHIGH, curses.COLOR_WHITE, curses.COLOR_GREEN)
        curses.init_pair(TABDIM, curses.COLOR_BLACK, curses.COLOR_GREEN)
        curses.init_pair(LOCALNETWORK, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(CONNECTOR, curses.COLOR_BLUE, curses.COLOR_BLACK)
        curses.init_pair(GLOBALDOMAIN, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(ACTIVEIP, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(ALERTDOMAIN, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(ACTIVEDEVICE, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(CLIENTMARK, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(ACTIVERX, curses.COLOR_BLUE, curses.COLOR_BLACK)
        curses.init_pair(ACTIVETX, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(MENUKEY, curses.COLOR_WHITE, curses.COLOR_BLACK)
        curses.init_pair(MENUTITLE, curses.COLOR_BLACK, curses.COLOR_CYAN)
    else:
        curses.init_pair(NORMAL, curses.COLOR_BLACK, curses.COLOR_WHITE)
        curses.init_pair(TOPBAR, curses.COLOR_GREEN, curses.COLOR_WHITE)
        curses.init_pair(TABHIGH, curses.COLOR_WHITE, curses.COLOR_GREEN)
        curses.init_pair(TABDIM, curses.COLOR_BLACK, curses.COLOR_GREEN)
        curses.init_pair(LOCALNETWORK, curses.COLOR_BLUE, curses.COLOR_WHITE)
        curses.init_pair(CONNECTOR, curses.COLOR_BLUE, curses.COLOR_WHITE)
        curses.init_pair(GLOBALDOMAIN, curses.COLOR_GREEN, curses.COLOR_WHITE)
        curses.init_pair(ACTIVEIP, curses.COLOR_BLUE, curses.COLOR_WHITE)
        curses.init_pair(ALERTDOMAIN, curses.COLOR_RED, curses.COLOR_WHITE)
        curses.init_pair(ACTIVEDEVICE, curses.COLOR_BLUE, curses.COLOR_WHITE)
        curses.init_pair(CLIENTMARK, curses.COLOR_GREEN, curses.COLOR_WHITE)
        curses.init_pair(ACTIVERX, curses.COLOR_BLUE, curses.COLOR_WHITE)
        curses.init_pair(ACTIVETX, curses.COLOR_RED, curses.COLOR_WHITE)
        curses.init_pair(MENUKEY, curses.COLOR_BLACK, curses.COLOR_WHITE)
        curses.init_pair(MENUTITLE, curses.COLOR_BLACK, curses.COLOR_CYAN)


# app init + main keypress/refresh loop
#
def main_app_loop(stdscr):
    global ui, GRAPH

    # graph chars from zero_value to max_value, e.g. '_⣀⣠⣤⣰⣴⣶⣼⣾⣿' or '_.-:=!I#$@'
    if curses.termname().decode('utf-8').startswith('linux'):
        GRAPH = '_░▒█'
    else:
        GRAPH = '_⣀⣠⣤⣰⣴⣶⣼⣾⣿'

    ui.scr = stdscr
    curses.noecho()
    curses.cbreak()
    curses.halfdelay(ui.refresh)
    curses.curs_set(0)
    curses.mousemask(MOUSEMASK)  # curses.ALL_MOUSE_EVENTS for no mask
    ui.scr.keypad(True)
    set_curses_colors()
    ui.scr.clear()
    ui.scr.refresh()

    while ui.running:
        refresh_data_and_screen()
        if ui.running:  # quit immediately both from keyboard and mouse
            try:
                ui.key = ui.scr.getch()
            except:
                ui.key = curses.ERR  # curses Ctrl-C work around



#    #           #####
 #    #         #     #  ####  #####  ###### ###### #    #
  #    #        #       #    # #    # #      #      ##   #
   #    #        #####  #      #    # #####  #####  # #  #
  #    #              # #      #####  #      #      #  # #
 #    #         #     # #    # #   #  #      #      #   ##
#    #           #####   ####  #    # ###### ###### #    #


# update the the whole screen; curses magically redraws only what has changed
#
def refresh_data_and_screen():
    global ui, backend, reader

    ui.debug = ''
    ##### sample of debugging during screen rendering
    ##### ui.debug += f" k={ui.key} "
    ##### ui.debug += f" w={ui.w} h={ui.h} term={curses.termname().decode('utf-8')} "

    ui.debug += f" k={ui.key} "

    handle_key_press()

    if not ui.running:  # quit
        return
    if not screen_check():  # resize
        return

    ui.devices = backend.get_devices()
    ui.clients = backend.get_clients()
    ui.statuses = reader.get_statuses()

    # as soon as there is first available device/client, show detail
    ui.devmenu = ui.devices if ui.all_devices else ui.clients
    if ui.selected not in ui.devmenu:
        ui.selected = ui.devmenu[0] if ui.devmenu else None

    ui.content = []  # rows with content
    draw_methods = (draw_content, draw_menu_status_bar)

    #tms = time.time()
    if not ui.selected:  # no data yet
        make_no_content()
    elif ui.detail:  # detail of device
        make_detail_content()
        draw_methods += (draw_detail_top_bar, draw_detail_title)
    else:  # list of devices/clients
        make_list_content()
        draw_methods += (draw_list_top_bar, draw_list_title)
    #ui.debug += f" make={round((time.time()-tms)*1000,3)}ms "

    #ui.debug += f" h={ui.neth} rows={ui.rows()} scr-bef={ui.scroll} "
    #tms = time.time()
    for m in draw_methods:
        m()
    #ui.debug += f" draw={round((time.time()-tms)*1000,3)}ms "
    #ui.debug += f" scr-aft={ui.scroll} "
    ui.debug += f" queue={ui.statuses['ql']} "

    # developer's helper
    if ui.show_debug and ui.debug:
        ui.scr.addnstr(ui.h-3, 3, ui.debug, ui.w-6, curses.color_pair(MENUTITLE))

    ui.scr.move(ui.h-1, ui.w-1)  # some terminals have cursor always on


# draw content prepared in ui.content
#
def draw_content():
    global ui
    # terminal resized?
    if ui.scroll+ui.neth > len(ui.content):
        ui.scroll = max(0, len(ui.content)-ui.neth)
    # draw content row by row, part by part; getch() in main loop refreshes screen
    firstrow = min(ui.scroll, len(ui.content))
    lastrow = min(ui.scroll+ui.neth, len(ui.content))
    for y, row in enumerate(ui.content[firstrow:lastrow]):
        if row[0] == RP:
            # row parts
            draw_row_parts(ui.reserved_top+y, row[1:])
        elif row[0] == GR:
            # graph
            draw_graph(ui.reserved_top+y, row[1], row[2], row[3], row[4], row[5])
    # clear rest of the screen
    if lastrow-firstrow < ui.neth:
        row = [['', NORMAL]]
        for y in range(lastrow-firstrow, ui.neth):
            draw_row_parts(ui.reserved_top+y, row)


# draw one row (all its parts)
#
def draw_row_parts(y, row):
    # row = [part, part, part, ...]
    # part = [text, opt-colorpair, opt-attron]
    # if no color or attr, then uses previous one until another is given
    global ui
    x = 0
    lastchar = 1 if y == ui.h-1 else 0
    for part in row:
        if len(part) > 1:
            ui.scr.attrset(curses.color_pair(part[1]))
        if len(part) > 2:
            ui.scr.attron(part[2])
        ui.scr.addnstr(y, x, part[0], ui.w-x-lastchar)
        x += len(part[0])
    # clear the rest of row with the last attrset+attron
    if x < ui.w:
        ui.scr.addstr(y, x, ' '*(ui.w-x-lastchar))
    if lastchar:
        ui.scr.insch(ui.h-1,ui.w-1,' ')


# get data and draw graph
#
def draw_graph(y, get_graph_method, macaddr, ip, tm, color):
    global ui

    dct = get_graph_method(macaddr, ip, tm)

    first_time = dct.pop('f')
    bar_len = dct.pop('l')
    time_pos = int(tm/bar_len)*bar_len  # time of last graph bar
    start_time = max(time_pos-(ui.w*bar_len), first_time)

    # empty line of correct length as there are no zero values in data
    bars = int((time_pos - start_time)/bar_len)+1  # time diff / bar_len
    draw_row_parts(y, [[rjust(GRAPH[0]*bars, ui.w), NORMAL, curses.A_DIM]])

    if dct:
        ui.scr.attrset(curses.color_pair(color))
        ui.scr.attron(curses.A_BOLD)
        max_val = max(dct.values())  # max value = 100 % in graph (last char of GRAPH)
        for tm in dct.keys():
            x = ui.w - int((time_pos-tm)/bar_len) - 1  # position according to time
            if 1 < x < ui.w:
                symbol = int(dct[tm]/max_val*(len(GRAPH)-2))  # % value -> corresponding symbol
                ui.scr.addstr(y, x, GRAPH[symbol+1])

    ui.scr.attrset(curses.color_pair(CONNECTOR))
    ui.scr.addstr(y, 0, '├ ' if ui.show_ip_stat else \
        ('└ ' if color == ACTIVERX or (color == ACTIVETX and not ui.show_rx_graph) else '├ '))


# terminal emulators may change screen size
#
def screen_check():
    global ui

    ui.h, ui.w = ui.scr.getmaxyx()
    if ui.w < 80 or ui.h < 12:
        ui.scr.clear()
        ui.scr.attrset(curses.color_pair(NORMAL))
        ui.scr.addstr(0, 0, center("Small terminal. Change size or 'q' to quit.", ui.w))
        return False
    return True



#    #          #    #
 #    #         #   #  ###### #   #    #####  #####  ######  ####   ####
  #    #        #  #   #       # #     #    # #    # #      #      #
   #    #       ###    #####    #      #    # #    # #####   ####   ####
  #    #        #  #   #        #      #####  #####  #           #      #
 #    #         #   #  #        #      #      #   #  #      #    # #    #
#    #          #    # ######   #      #      #    # ######  ####   ####


# key press actions
#
def handle_key_press():
    global ui, backend

    previous = ui.selected

    if ui.key == curses.KEY_MOUSE:
        # work around: sometimes it raises exception in getmouse()
        try:
            _, mx, my, _, me = curses.getmouse()   # mouse x, y, event
            ui.key = handle_mouse(mx, my, me)
        except:
            ui.key == curses.ERR

    if ui.key == curses.ERR:
        # no key
        return

    if ui.detail and ui.selected:
        # keys in detail view and only when not empty
        if ui.key == curses.KEY_LEFT or ui.key == 353: # Shift-Tab
            if ui.selected in ui.devmenu:
                idx = next((i for i, d in enumerate(ui.devmenu) if ui.selected == d), 0)
                idx = max(idx-1, 0)
                ui.selected = ui.devmenu[idx]

        elif ui.key == curses.KEY_RIGHT or ui.key == 9: # Tab
            if ui.selected in ui.devmenu:
                idx = next((i for i, d in enumerate(ui.devmenu) if ui.selected == d), 0)
                idx = min(idx+1, len(ui.devmenu)-1)
                ui.selected = ui.devmenu[idx]

        elif ui.key == curses.KEY_F8:
            backend.clear_device_stats(ui.selected)
            ui.scroll = 0

        elif ui.key == 284:  # Shift+F8
            backend.clear_device_all(ui.selected)
            ui.scroll = 0

        elif ui.key == ord('s'):
            ui.show_tx_graph = not ui.show_tx_graph

        elif ui.key == ord('r'):
            ui.show_rx_graph = not ui.show_rx_graph

        elif ui.key == ord('g'):
            ui.sec_graph = not ui.sec_graph

        elif ui.key == ord('i'):
            ui.show_ip_stat = not ui.show_ip_stat

        elif ui.key == ord('l'):
            ui.show_local = not ui.show_local

        # elif ui.key == ord('c'):
        #     ui.show_cnames = not ui.show_cnames

        elif ui.key == ord('m'):
            ui.show_more = None if ui.show_more == 'mdns' else 'mdns' # multicast dns
            ui.scroll = 0

        elif ui.key == ord('b'):
            ui.show_more = None if ui.show_more == 'bdns' else 'bdns' # blocked dns
            ui.scroll = 0

    # global keys
    if ui.key == curses.KEY_UP:
        ui.scroll = max(0, ui.scroll-1)

    elif ui.key == 339: # PgUp
        ui.scroll = max(0, ui.scroll-ui.neth)

    elif ui.key == curses.KEY_DOWN:
        ui.scroll = min(max(0, ui.rows()-ui.neth), ui.scroll+1)

    elif ui.key == 338: # PgDn
        ui.scroll = min(max(0, ui.rows()-ui.neth), ui.scroll+ui.neth)

    elif ui.key == curses.KEY_HOME:
        ui.scroll = 0

    elif ui.key == curses.KEY_END:
        ui.scroll = max(0, ui.rows()-ui.neth)

    elif ui.key == curses.KEY_F3:
        ui.highlight = not ui.highlight

    elif ui.key == curses.KEY_F4:
        ui.all_devices = not ui.all_devices

    elif ui.key == curses.KEY_F5:
        ui.detail = not ui.detail
        ui.scroll = 0

    elif ui.key == curses.KEY_F6:
        ui.active_first = not ui.active_first
        ui.scroll = 0

    elif ui.key == ord('t'):
        ui.abs_time = not ui.abs_time

    elif ui.key == ord('T'):
        ui.dark_theme = not ui.dark_theme
        set_curses_colors()

    elif ui.key == ord('+'):
        ui.refresh = min(ui.refresh+5, 50)
        curses.halfdelay(ui.refresh)

    elif ui.key == ord('-'):
        ui.refresh = max(ui.refresh-5, 5)
        curses.halfdelay(ui.refresh)

    elif ui.key == ord('p'):
        ui.debug += " paused "
        wait_for_any_key()

    elif ui.key in (ord('h'), curses.KEY_F1):
        show_help()

    elif ui.key in (ord('q'), curses.KEY_F10):
        ui.running = False

    # keys for devs and code readers
    elif ui.key == 144: # AltGr+D
        ui.show_debug = not ui.show_debug

    elif ui.key == 172: # AltGr+E
        if ui.selected and ui.statuses['time']:
            if backend.export_device(ui.selected, ui.statuses['time']):
                ui.debug += " Export saved. "
            else:
                ui.debug += " Export failed. "

    # go to top when device was changed
    if previous != ui.selected:
        ui.scroll = 0


# pause/help 'press any key'
#
def wait_for_any_key():
    global ui

    answer = curses.ERR
    while answer == curses.ERR:
        try:
            answer = ui.scr.getch()
        except:
            answer = 42  # The Answer not only to curses Ctrl-C


# mouse actions
#
def handle_mouse(mx, my, me):
    global ui

    ret = curses.ERR

    if me == curses.BUTTON1_CLICKED:  # left button
        # click on menu
        if my == ui.h-1:
            x = 0
            for mi in MENU:
                x += len(mi[0])+len(mi[3])
                if mx < x:
                    ret = mi[1]  # return key
                    break
        # click on screen on something
        elif not ui.scr.inch(my,mx) & 0xFF == ' ':
            clicked_on = get_macaddr_under_mouse(my, mx, 17)  # 17=MAC addr length
            if clicked_on in ui.devmenu:
                ui.selected = clicked_on
                ui.detail = True

    elif me == curses_MOUSE_WHEEL_UP:
        wheelstep = min(10, ui.neth)
        ui.scroll = max(0, ui.scroll-wheelstep)

    elif me == curses_MOUSE_WHEEL_DOWN:
        wheelstep = min(10, ui.neth)
        ui.scroll = max(0, min(ui.scroll+wheelstep, ui.rows()-ui.neth))

    # # possible future feature for x-term: open IP or domain in browser with whois info
    # elif me == curses.BUTTON1_DOUBLE_CLICKED:  # left button double click
    #     ui.debug += f" LEFT-DOUBLE "
    #     pass

    return ret


# read screen if there is a MAC address under the mouse click
#
def get_macaddr_under_mouse(my, mx, n):
    global ui
    f = max(0, mx-n+1)     # first char left from mouse
    l = min(mx+n, ui.w-1)  # last char
    txt = ui.scr.instr(my, f, l-f).decode('utf-8')
    words = txt.split(' ')
    longest = max(words, key=len)
    return longest if len(longest) == 17 else None



#    #          #######
 #    #            #     ####  #####
  #    #           #    #    # #    #
   #    #          #    #    # #    #
  #    #           #    #    # #####
 #    #            #    #    # #
#    #             #     ####  #


def devices_or_clients():
    global ui

    txt = "Device" if ui.all_devices else "Client"
    if len(ui.devmenu) > 1:
        txt = f"{len(ui.devmenu)} {txt}s"
    elif len(ui.devmenu) == 1:
        txt = f"{len(ui.devmenu)} {txt}"
    elif not len(ui.devmenu):
        txt = f"No {txt.lower()}"
    return txt


def stats_labels():
    txt = ''
    for label in ("Active", "Sent", "Received", "Queries", "Domains", "Servers", "Packets"):
        txt += rjust(label,9)
    txt += '  ' + "IP addresses"
    return txt


# top bar for list of devices
#
def draw_list_top_bar():
    global ui

    row = []
    part1 = devices_or_clients()
    if ui.all_devices:
        part2 = " (MAC addresses sending network packets)"
    else:
        part2 = " (computers, smartphones, TVs... using DNS/DHCP)"
    spacer = ' '*((ui.w-len(part1)-len(part2))//2)  # center row
    row.append([spacer, TABDIM])
    row.append([part1, TABHIGH, curses.A_BOLD])
    row.append([part2, TABDIM])
    draw_row_parts(0, row)


# column titles above list of devices
#
def draw_list_title():
    global ui

    txt = '  ' if ui.all_devices else ''  # 'C' mark for clients
    txt += ljust("MAC address",17)
    txt += stats_labels()
    draw_row_parts(1, [[txt, TABDIM]])


# top menu (tabs with devices) for detail
#
def draw_detail_top_bar():
    global ui

    txt = devices_or_clients() + ':'
    devtxt = ''
    for d in ui.devmenu:
        devtxt = devtxt + ' ' + d + ' '  # _macaddress_

    # TODO: improve movements from left to right and back; this is not too nice

    # shift macaddr list if it will not fit screen width
    sel_dev = ' ' + ui.selected + ' '
    pos = devtxt.find(sel_dev)
    if pos+len(sel_dev) > ui.w-len(txt)-3:
        # will not fit, shift (make it last one)
        shift = pos - (ui.w-7) + len(txt) + len(sel_dev) # 7=  ' <<<' and '>>>'
        devtxt = ' <<<' + devtxt[shift:]
    devtxt = txt + devtxt
    if len(devtxt) > ui.w:
        devtxt = devtxt[:(ui.w-3)] + '>>>'

    ui.scr.addstr(0, 0, ljust('', ui.w), curses.color_pair(NORMAL))  # clear
    # draw top bar and highlight selected device ('tab/panel' style)
    ui.scr.addstr(0, 0, devtxt, curses.color_pair(TOPBAR))
    # TODO: split label and menu
    ui.scr.addstr(0, 0, txt, curses.color_pair(NORMAL))
    # highlight selected
    ui.scr.attrset(curses.color_pair(TABHIGH))
    ui.scr.attron(curses.A_BOLD)
    pos = devtxt.find(sel_dev)
    ui.scr.addstr(0, pos, sel_dev, )


# stats + column titles above detail
#
def draw_detail_title():
    global ui

    # IP addresses of the device
    txt = "IP: " + (ui.device['ip'] if ui.device['ip'] else "--")
    if ui.device['hn']:
        txt += "  Hostname: " + ui.device['hn']

    draw_row_parts(1, [[center(txt, ui.w), TABHIGH, curses.A_BOLD]])

    # two row detailed statistics
    is_highlighted = ui.highlight and ui.device['la'] > HIGHLIGHTTIME
    COLOR = NORMAL
    NUM_ATTR = curses.A_BOLD if is_highlighted else NORMAL
    LBL_ATTR = curses.A_BOLD if is_highlighted else curses.A_DIM
    spacer = ["    ", COLOR, LBL_ATTR]

    row = []
    row.append([fmt_volume(ui.device['tx']), COLOR, NUM_ATTR])
    row.append([" Sent", ACTIVETX, LBL_ATTR if is_highlighted else NORMAL])
    row.append(spacer)
    row.append([fmt_volume(ui.device['rx']), COLOR, NUM_ATTR])
    row.append([" Rcvd", ACTIVERX, LBL_ATTR if is_highlighted else NORMAL])
    row.append(spacer)
    row.append([fmt_volume(ui.device['dnsd'], base=1000), COLOR, NUM_ATTR])
    row.append([" Domains", COLOR, LBL_ATTR])
    row.append(spacer)
    row.append([fmt_volume(ui.device['conn'], base=1000), COLOR, NUM_ATTR])
    row.append([" Destinations", COLOR, LBL_ATTR])
    draw_row_parts(2, row)

    row = []
    row.append([fmt_volume(ui.device['tp'], base=1000), COLOR, LBL_ATTR]);
    row.append([" pkts"])
    row.append(spacer)
    row.append([fmt_volume(ui.device['rp'], base=1000)])
    row.append([" pkts"])
    row.append(spacer)
    row.append([fmt_volume(ui.device['dnsq'], base=1000)])
    row.append([" Queries"])
    row.append(spacer)
    row.append([fmt_volume(ui.device['pkts'], base=1000)])
    row.append([" total pkts"])
    draw_row_parts(3, row)

    # protocols/ports the device communicate to
    draw_row_parts(4, [[' '.join(list(ui.device['prot'])), NORMAL]])

    # column labels for the main content - connection details
    txt = ''
    if not ui.show_more:
        if ui.show_ip_stat:
            txt = '  ' \
                + rjust("IP address", ui.device['colw'] if ui.conns else 10) \
                + " Loc  Active     Sent Received  Protocols"
        # column label for graph
        if ui.show_rx_graph or ui.show_tx_graph:
            txt += rjust( f"Last {ui.w-2} " + ("sec" if ui.sec_graph else "min"), ui.w-len(txt))
    draw_row_parts(5, [[txt, TABDIM]])



#    #          #     #
 #    #         ##   ## ###### #    # #    #
  #    #        # # # # #      ##   # #    #
   #    #       #  #  # #####  # #  # #    #
  #    #        #     # #      #  # # #    #
 #    #         #     # #      #   ## #    #
#    #          #     # ###### #    #  ####


# bottom menu bar and status bar
#
def draw_menu_status_bar():
    global ui, backend

    x = 0  # remaining chars for status bar
    row = []
    for mi in MENU:
        row.append([mi[0], MENUKEY])  # Key
        x += len(mi[0])
        txt = mi[3]                   # Text
        if mi[2] == 'h' and not ui.highlight:
            txt = mi[4]
        elif mi[2] == 'd' and not ui.all_devices:
            txt = mi[4]
        elif mi[2] == 'l' and not ui.detail:
            txt = mi[4]
        elif mi[2] == 's' and not ui.active_first:
            txt = mi[4]
        row.append([txt, MENUTITLE])
        x += len(txt)

    # status bar for the rest of the width
    txt = fmt(ui.statuses['pkts'])
    if ui.statuses['err']:
        txt +=" ERR"
    else:
        txt += '' if ui.statuses['live'] else " END"

    # show time/performance if enough space
    if ui.statuses['pkts'] > 0:
        if ui.abs_time:
            part = fmt_time(ui.statuses['time']-ui.timezone_correction, variant=1)
        else:
            part = rel_time(ui.statuses['time']-ui.statuses['snc']+1, variant=2)
        if x+len(txt)+len(part)+3 < ui.w-1:
            txt = part + ' | ' + txt

    if ui.statuses['live']:
        part = f"{ui.statuses['perf']} p/s"
        if x+len(txt)+len(part)+3 < ui.w-1:
            txt = part + ' | ' + txt

    row.append([rjust(txt, ui.w-1-x), MENUTITLE])
    draw_row_parts(ui.h-1, row)



#    #           #####
 #    #         #     #  ####  #    # ##### ###### #    # #####
  #    #        #       #    # ##   #   #   #      ##   #   #
   #    #       #       #    # # #  #   #   #####  # #  #   #
  #    #        #       #    # #  # #   #   #      #  # #   #
 #    #         #     # #    # #   ##   #   #      #   ##   #
#    #           #####   ####  #    #   #   ###### #    #   #


# content of empty screen before some data are available
#
def make_no_content():
    global ui

    ui.set_layout(0, 1)
    ui.content.append([RP, ['', NORMAL]])
    ui.content.append([RP,
        [center(devices_or_clients() + " has been seen in network traffic so far.", ui.w)]])
    ui.content.append([RP, ['']])
    if ui.statuses['live']:
        ui.content.append([RP, [center(f"Packet reader is live.", ui.w)]])
    else:
        if ui.statuses['err']:
            ui.content.append([RP, [center(f"Packet reader has finished with errors.", ui.w)]])
        else:
            ui.content.append([RP, [center(f"Packet reader has finished.", ui.w)]])
        ui.content.append([RP, [center(f"Nothing else will happen.", ui.w)]])


# content for device/client list w/ statistics
#
def make_list_content():
    global ui, backend

    ui.device = None
    ui.conns = None

    ui.set_layout(2, 1)
    lst = []
    sortkey = 'la' if ui.active_first else 'fa'
    for macaddr in ui.devmenu:
        devstat = backend.get_device_statistics(macaddr, ui.statuses['time'])
        lst.append([devstat[sortkey], macaddr, \
            devstat['rx'], devstat['tx'], devstat['dnsq'], devstat['dnsd'], \
            devstat['conn'], devstat['pkts'], devstat['la'], devstat['ip']])
    lst.sort(reverse=True)

    for d in lst:
        cols = [RP]
        # highlight currently active communication
        is_highlighted = ui.highlight and d[8] > HIGHLIGHTTIME
        COLOR, ATTR = (ACTIVEDEVICE, curses.A_BOLD) if is_highlighted else (NORMAL, curses.A_DIM)
        # mark clients
        txt = ('C ' if d[1] in ui.clients else '  ') if ui.all_devices else ''
        cols.append([txt, CLIENTMARK, ATTR])
        # time
        txt = d[1] + rjust("now" if is_highlighted else rel_time(d[8],variant=1), 9)
        cols.append([txt, COLOR, ATTR])
        # colored columns with data volume
        cols.append([rjust(fmt_volume(d[3]),9), ACTIVETX if is_highlighted else COLOR, ATTR])
        cols.append([rjust(fmt_volume(d[2]),9), ACTIVERX if is_highlighted else COLOR, ATTR])
        # the rest
        txt = rjust(str(d[4]), 9) + rjust(str(d[5]), 9) \
            + rjust(str(d[6]), 9) + rjust(str(d[7]), 9) + '  ' + d[9]
        cols.append([txt, COLOR, ATTR])
        ui.content.append(cols)


# additional informations from multicast dns querries
#
def make_multicast_content():
    global ui
    mdns = backend.get_device_mdns(ui.selected)
    if mdns:
        k = list(mdns.keys())
        k.sort()
        for key in k:
            ui.content.append([RP, [key, ACTIVEDEVICE]])
            v = list(mdns[key])
            v.sort()
            for value in v:
                ui.content.append([RP, ['    '+value, NORMAL]])
            ui.content.append([RP, ['', NORMAL]])
    else:
        ui.content.append([RP, ["", NORMAL]])
        ui.content.append([RP, [center("No multicast DNS traffic from this device yet.", ui.w)]])
        ui.content.append([RP, ["", NORMAL]])
    ui.content.append([RP, ["", NORMAL]])
    ui.content.append([RP, [center("Press 'm' to show/hide this multicast info...", ui.w)]])


# information about dns querries blocked by dns server
#
def make_blocked_dns_content():
    global ui
    ip2dns = backend.get_device_dnsreplies(ui.selected)
    if ip2dns:
        ips = list(ip2dns.keys())
        ips.sort()
        for ip in ips:
            if ip.startswith('0.') or ip.startswith('127.') or ip.startswith('::'):
                ui.content.append([RP, [ip, ACTIVEDEVICE]])
                for addr in ip2dns[ip]:
                    ui.content.append([RP, ['    '+addr, NORMAL]])
                ui.content.append([RP, ['', NORMAL]])
        if not ui.content:
            ui.content.append([RP, ["", NORMAL]])
            ui.content.append([RP, [center("No DNS querries blocked by DNS server yet.", ui.w)]])
            ui.content.append([RP, ["", NORMAL]])
    else:
        ui.content.append([RP, ["", NORMAL]])
        ui.content.append([RP, [center("No DNS traffic from this device yet.", ui.w)]])
        ui.content.append([RP, ["", NORMAL]])
    ui.content.append([RP, ["", NORMAL]])
    ui.content.append([RP, [center("Press 'b' to show/hide this DNS-blocked info...", ui.w)]])


# details of network activity for selected mac address (connections, mdns info, etc.)
#
def make_detail_content():
    global ui, backend

    ui.set_layout(6, 1)

    ui.device = backend.get_device_statistics(ui.selected, ui.statuses['time'])

    # additional info with separate view
    if ui.show_more == 'mdns':
        make_multicast_content()
        return
    if ui.show_more == 'bdns':
        make_blocked_dns_content()
        return

    # details - list of connections
    ui.conns = backend.get_device_connections(ui.selected, ui.statuses['time'])
    if ui.conns:
        ip2dns = backend.get_device_dnsreplies(ui.selected)

        # sort
        lst = []
        sortkey = 'la' if ui.active_first else 'fa'
        for ip in ui.conns.keys():
            # uncoment, if only transmitting IPs are interesting, e.g. hide incoming broadcasts
            ##### if ui.conns[ip]['tx'] > 0:
            lst.append([ui.conns[ip][sortkey], ip])

        lst.sort(reverse=True)

        for c in lst:  # connection in sorted list of IP connections
            ip = c[1]

            is_listed = True
            is_highlighted = ui.highlight and ui.conns[ip]['la'] > HIGHLIGHTTIME

            # TODO: show/hide cnames
            # backend.get_device_dnscnames(ui.selected)

            # name of IP connection based on DNS querries and IP address type
            txt = backend.get_device_ip_name(ui.selected, ip)
            if not ui.show_ip_stat:
                txt += ' '+ip
            # color of the name
            if ip in ip2dns:
                if ui.conns[ip]['glob']:
                    COLOR, ATTR = \
                        (GLOBALDOMAIN, curses.A_BOLD) if is_highlighted else (GLOBALDOMAIN, NORMAL)
                else:
                    is_listed = ui.show_local
                    COLOR, ATTR = \
                        (LOCALNETWORK, curses.A_BOLD) if is_highlighted else (LOCALNETWORK, NORMAL)
            else:
                if ui.conns[ip]['mult'] or ui.conns[ip]['priv'] or ui.conns[ip]['rsrv']:
                    is_listed = ui.show_local
                    COLOR, ATTR = \
                        (LOCALNETWORK, curses.A_BOLD) if is_highlighted else (LOCALNETWORK, NORMAL)
                elif ui.conns[ip]['glob']:
                    COLOR, ATTR = \
                        (ALERTDOMAIN, curses.A_BOLD) if is_highlighted else (ALERTDOMAIN, NORMAL)
                else:
                    COLOR, ATTR = (NORMAL, curses.A_BOLD) if is_highlighted else (NORMAL, NORMAL)

            if is_listed:
                ui.content.append([RP, [txt, COLOR, ATTR]])

                # graphs will retrieve data only when row is visible, via method stored in row data
                if ui.show_tx_graph:
                    if ui.sec_graph:
                        method = backend.get_device_ip_tx_sec_graph
                    else:
                        method = backend.get_device_ip_tx_min_graph
                    ui.content.append([GR, method, ui.selected, ip, ui.statuses['time'], ACTIVETX])

                if ui.show_rx_graph:
                    if ui.sec_graph:
                        method = backend.get_device_ip_rx_sec_graph
                    else:
                        method = backend.get_device_ip_rx_min_graph
                    ui.content.append([GR, method, ui.selected, ip, ui.statuses['time'], ACTIVERX])

                # statistics for an IP address (cols = columns, then store them into row content)
                if ui.show_ip_stat:
                    cols = [RP]
                    COLOR, ATTR = (ACTIVEIP, curses.A_BOLD) if is_highlighted else (NORMAL, NORMAL)
                    cols.append(['└' + '─'*(ui.device['colw']-len(ip)) + ' ', CONNECTOR])
                    cols.append([ip, COLOR, ATTR])
                    if (not ui.conns[ip]['cntr']) and \
                        (ui.conns[ip]['mult'] or ui.conns[ip]['rsrv'] or ui.conns[ip]['priv']):
                        cols.append([' ~~', COLOR, ATTR])  # local network symbol
                    else:
                        cols.append([rjust(ui.conns[ip]['cntr'],3), COLOR, ATTR])
                    if is_highlighted:
                        elapsed = "now"
                    else:
                        elapsed = rel_time(ui.conns[ip]['la'], variant=1)
                    cols.append([rjust(elapsed, 9), COLOR, ATTR])
                    cols.append([rjust(fmt_volume(ui.conns[ip]['tx']), 9),
                        ACTIVETX if is_highlighted else COLOR, ATTR])
                    cols.append([rjust(fmt_volume(ui.conns[ip]['rx']), 9),
                        ACTIVERX if is_highlighted else COLOR, ATTR])
                    cols.append(['  ' + ' '.join(list(ui.conns[ip]['prot'])), COLOR, ATTR])
                    ui.content.append(cols)

    if not ui.content:
        ui.content.append([RP, ['', NORMAL]])
        ui.content.append([RP, [center("No data transmitted over IP", ui.w), NORMAL]])
        ui.content.append([RP, [center("from device "+ui.selected, ui.w)]])
        if not ui.show_local:
            ui.content.append([RP, [center("to internet.", ui.w)]])
            ui.content.append([RP])
            ui.content.append([RP,
                [center("(Local network addresses are hidden. Press 'l' to show.)", ui.w)]])


# number format
#
def fmt(num):
    return f"{num:,}".replace(",", " ")


# display number into 7 chars: 999_999 or 9.999_M
#
def fmt_volume(num, base=1024):
    if num <= 999999:
        txt = f"{num:7,}".replace(',', ' '); unit = ''
    elif num <= 999.9*(base**2):
        num = round(num/base/base,3); unit = 'M'
    elif num <= 999.9*(base**3):
        num = round(num/base/base/base,3); unit = 'G'
    elif num <= 999.9*(base**4):
        num = round(num/base/base/base/base,3); unit = 'T'
    else:
        txt = '*'*7; unit = ''
    if unit:
        if round(num,3) < 10:
            txt = f"{round(num,3):1.3f}"
        elif round(num,2) < 100:
            txt = f"{round(num,2):1.2f}"
        else:
            txt = f"{round(num,1):1.1f}"
    return txt + (' '+unit if unit else '')


# left, center, right justify text to exact length, even smaller or zero
#
def ljust(t, n):
    if len(t) > n:
        t = t[:n] if n > 0 else ''
    return t.ljust(n)

def center(t, n):
    if len(t) > n:
        l = round(len(t)/2 - n/2)
        t = t[l:(l+n)] if n > 0 else ''
    return t.center(n)

def rjust(t, n):
    if len(t) > n:
        t = t[-n:] if n > 0 else ''
    return t.rjust(n)



#    #          #     #
 #    #         #     # ###### #      #####
  #    #        #     # #      #      #    #
   #    #       ####### #####  #      #    #
  #    #        #     # #      #      #####
 #    #         #     # #      #      #
#    #          #     # ###### ###### #


def show_help():
    global ui

    ui.set_layout(0, 0)
    ui.content = []
    ui.content.append([RP,
        ["wireowl " + VERSION + " - network traffic statistics (c) 2021-2022 Jiri Rozvaril.",
        LOCALNETWORK]])
    ui.content.append([RP,
        ["Released under GNU GPLv2 license. Run with -h for usage info.",
        LOCALNETWORK]])

    ui.content.append([RP])
    colw = 8
    ui.content.append([RP,
        [" Up/Down, PgUp/PgDn, Home/End:", LOCALNETWORK],
        [" scroll in a long list", NORMAL]])
    ui.content.append([RP,
        [rjust("F3: ",colw), LOCALNETWORK],
        ["toggle active communication highlighting", NORMAL]])
    ui.content.append([RP,
        [rjust("F4: ",colw), LOCALNETWORK],
        ["show all devices/clients only", NORMAL]])
    ui.content.append([RP,
        [rjust("F5: ",colw), LOCALNETWORK],
        ["toggle list/detail", NORMAL]])
    ui.content.append([RP,
        [rjust("F6: ",colw), LOCALNETWORK],
        ["toggle sort order by last activity/first appearance", NORMAL]])
    ui.content.append([RP,
        [rjust("t: ",colw), LOCALNETWORK],
        ["toggle absolute/relative time", NORMAL]])
    ui.content.append([RP,
        [rjust("T: ",colw), LOCALNETWORK],
        ["toggle dark/light theme", NORMAL]])
    ui.content.append([RP,
        [rjust("+ -: ",colw), LOCALNETWORK],
        [f"adjust refresh speed (now {ui.refresh/10:,}s)", NORMAL]])
    ui.content.append([RP,
        [rjust("p: ",colw), LOCALNETWORK],
        ["pause", NORMAL]])

    ui.content.append([RP])
    ui.content.append([RP,
        ["Detail view:", NORMAL]])
    ui.content.append([RP,
        [" Right/Left, Tab/Shift-Tab:", LOCALNETWORK],
        [" select device", NORMAL]])
    ui.content.append([RP,
        [rjust("s r: ",colw), LOCALNETWORK],
        ["show/hide sent/received data graph", NORMAL]])
    ui.content.append([RP,
        [rjust("g: ",colw), LOCALNETWORK],
        ["toggle second/minute graphs", NORMAL]])
    ui.content.append([RP,
        [rjust("i: ",colw), LOCALNETWORK],
        ["show/hide IP address details", NORMAL]])
    ui.content.append([RP,
        [rjust("l: ",colw), LOCALNETWORK],
        ["show/hide local network addresses", NORMAL]])
    # TODO: CNAMES
    # ui.content.append([RP,
    #     [rjust("c: ",colw), LOCALNETWORK],
    #     ["show/hide CNAMES next to domain", NORMAL]])
    ui.content.append([RP,
        [rjust("m b: ",colw), LOCALNETWORK],
        ["show/hide device's multicast/blocked querries", NORMAL]])
    ui.content.append([RP,
        [rjust("F8: ",colw), LOCALNETWORK],
        ["clear connections  ", NORMAL],
        ["Shift+F8: ", LOCALNETWORK],
        ["clear all", NORMAL]])

    ui.content.append([RP])
    ui.content.append([RP,
        [rjust("F1 h: ",colw), LOCALNETWORK],
        ["show this help screen", NORMAL]])
    ui.content.append([RP,
        [rjust("F10 q: ",colw), LOCALNETWORK],
        ["quit", NORMAL]])

    ui.content.append([RP])
    ui.content.append([RP,
        ["Press any key to return.", LOCALNETWORK],
        ["", NORMAL]])

    scroll = ui.scroll
    ui.scroll = 0
    draw_content()
    ui.scroll = scroll
    wait_for_any_key()
