#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import os
import shutil
import time
import urllib.request
from datetime import datetime
from datetime import timedelta
import sre_yield
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

SCRIPT_LOC = os.path.realpath(__file__)
CWD = os.path.dirname(SCRIPT_LOC)

SKIP_IPV4 = os.environ.get('SKIP_IPV4')
SKIP_IPV6 = os.environ.get('SKIP_IPV6')

IPV4 = os.environ.get('IPV4')
IPV6 = os.environ.get('IPV6')

REDIRECT_IPV4 = os.environ.get('REDIRECT_IPV4')
REDIRECT_IPV6 = os.environ.get('REDIRECT_IPV6')

DNS_RESTART = os.environ.get('DNS_RESTART')

# This may trigger a command injection warning on linters but it is safe as
# there is no user input involved.
SHELL_IPV4 = os.popen('ip route get 1.1.1.1 2> /dev/null | ' +  # nosec
                      'awk -F"src " \'NR==1{split($2,a," ");' +
                      'print a[1]}\'').read().rstrip()

# This may trigger a command injection warning on linters but it is safe as
# there is no user input involved.
SHELL_IPV6 = os.popen('ip route get 2606:4700:4700::1111 ' +  # nosec
                      '2> /dev/null | ' +
                      'awk -F"src " \'NR==1{split($2,a," ");' +
                      'print a[1]}\'').read().rstrip()

if not IPV4 and (not SKIP_IPV4 or SKIP_IPV4 == "false"):
    IPV4 = SHELL_IPV4

if not IPV6 and (not SKIP_IPV6 or SKIP_IPV6 == "false"):
    IPV6 = SHELL_IPV6

if not IPV4 or SKIP_IPV4 != "false":
    IPV4 = '0.0.0.0'

if not IPV6 or SKIP_IPV6 != "false":
    IPV6 = '::'

if not REDIRECT_IPV4 and (not SKIP_IPV4 or SKIP_IPV4 == "false"):
    REDIRECT_IPV4 = SHELL_IPV4

if not REDIRECT_IPV6 and (not SKIP_IPV6 or SKIP_IPV6 == "false"):
    REDIRECT_IPV6 = SHELL_IPV6

if not REDIRECT_IPV4 or SKIP_IPV4 != "false":
    REDIRECT_IPV4 = '0.0.0.0'

if not REDIRECT_IPV6 or SKIP_IPV6 != "false":
    REDIRECT_IPV6 = '::'

if not DNS_RESTART:
    DNS_RESTART = 'systemctl restart bind9 &> /dev/null'


def make_a(domains):
    a_record = ''

    for domain in domains:
        regex_list = []

        if domains[domain] == '{{SELF}}':
            domains[domain] = REDIRECT_IPV4

        for each in sre_yield.AllStrings(domain):
            regex_list.append(each)

        for entry in regex_list:
            a_record += f'{entry} IN A {domains[domain]}\n'

    return a_record


def make_aaaa(domains):
    aaaa_record = ''

    for domain in domains:
        regex_list = []

        if domains[domain] == '{{SELF}}':
            domains[domain] = REDIRECT_IPV6

        for each in sre_yield.AllStrings(domain):
            regex_list.append(each)

        for entry in regex_list:
            aaaa_record += f'{entry} IN AAAA {domains[domain]}\n'

    return aaaa_record


def make_zone(info_object):
    yyyymmdd = datetime.today().strftime('%Y%m%d')
    a_records = make_a(info_object['ip_v4'])
    aaaa_records = make_aaaa(info_object['ip_v6'])
    zone = f'''$TTL 3600
;; SOA Record
@ IN SOA ns.the.gate root.the.gate. {yyyymmdd} 7200 3600 86400 3600

;; NS Records
@ IN NS ns.the.gate.

'''
    zone += f';; A Records\n{a_records}\n;; AAAA Records\n{aaaa_records}'

    return bytes(zone, 'utf-8')


def make_bind_conf(zones):
    conf = ''

    for root_domain in zones:
        conf += f'zone "{root_domain}" {{\n'
        conf += '    type master;\n'
        if zones[root_domain] == '{{BLOCKED}}':
            conf += '    file "/etc/bind/zones/db.blocked";\n'
        else:
            conf += f'    file "/etc/bind/zones/db.{root_domain}";\n'
        conf += '};\n\n'

    return bytes(conf, 'utf-8')


def make_blocked_zone(zone_dir):
    with open(os.path.join(zone_dir, 'db.blocked'), 'wb+') as buf:
        buf.write(bytes('''$TTL 3600
;; SOA Record
@ IN SOA ns.the.gate root.the.gate. 20200103 7200 3600 86400 3600

;; NS Records
@ IN NS ns.the.gate.

;; A Records
@ IN A 0.0.0.0
* IN A 0.0.0.0

;; AAAA Records
@ IN AAAA ::
* IN AAAA ::
''', 'utf-8'))


def make_the_gate(zone_dir, conf_file):
    with open(os.path.join(zone_dir, 'db.the.gate'), 'wb+') as buf:
        buf.write(bytes(f'''$TTL 3600
;; SOA Record
@ IN SOA ns.the.gate root.the.gate. 20200103 7200 3600 86400 3600

;; NS Records
@ IN NS ns.the.gate.

;; A Records
@ IN A {REDIRECT_IPV4}
ns IN A {REDIRECT_IPV4}
* IN A 0.0.0.0

;; AAAA Records
@ IN AAAA {REDIRECT_IPV6}
ns IN AAAA {REDIRECT_IPV6}
* IN AAAA ::
''', 'utf-8'))

    with open(conf_file, 'ab+') as buf:
        buf.write(bytes('''zone "the.gate" {
    type master;
    file "/etc/bind/zones/db.the.gate";
};
''', 'utf-8'))


def main(zone_json, zone_dir, conf_file):
    shutil.rmtree(zone_dir, ignore_errors=True)
    if not os.path.exists(zone_dir):
        os.makedirs(zone_dir, exist_ok=True)

    for root_domain in zone_json:
        if zone_json[root_domain] != '{{BLOCKED}}':
            with open(os.path.join(zone_dir,
                                   f'db.{root_domain}'), 'wb+') as buf:
                buf.write(make_zone(zone_json[root_domain]))

    with open(conf_file, 'wb+') as buf:
        buf.write(make_bind_conf(zone_json))

    make_blocked_zone(zone_dir)
    make_the_gate(zone_dir, conf_file)


def watchdog():
    event_handler = WatchdogHandler()
    observer = Observer()
    observer.schedule(event_handler,
                      path='/opt/dns-config-watchdog/',
                      recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


def watchdog_cwd():
    event_handler = WatchdogHandlerCWD()
    observer = Observer()
    observer.schedule(event_handler,
                      path=os.path.join(CWD),
                      recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


def refresh_dns_zones():
    if not ARGS.skip_refresh:
        # WARNING: Possible command injection here
        # It *shouldn't* be an issue as the command is grabbed at runtime and
        # not updated. To run this script you would already have to have
        # execution. I am not going to add a directive to ignore this line in
        # the linter because it is accurate if an attacker where to be able to
        # edit your ENV variables and then you were to run the script it would
        # run their commands. A possible fix is checking if the command is in
        # a whitelist of known commands for restarting the DNS server on
        # various systems... or not including the command ENV and checking for
        # which command to use within the script itself.
        os.popen(DNS_RESTART)


class WatchdogHandler(FileSystemEventHandler):
    def __init__(self):
        self.last_modified = datetime.now()

    def on_modified(self, event):
        if datetime.now() - self.last_modified < timedelta(seconds=1):
            return
        else:
            self.last_modified = datetime.now()

        if event.src_path == '/opt/dns-config-watchdog/zones.json':
          with open('/opt/dns-config-watchdog/zones.json', 'rb') as buf:
              zones = json.loads(buf.read())
          shutil.rmtree('/etc/bind/zones/', ignore_errors=True)
          main(zones, '/etc/bind/zones/', '/etc/bind/named.conf.local')
          refresh_dns_zones()


class WatchdogHandlerCWD(FileSystemEventHandler):
    def __init__(self):
        self.last_modified = datetime.now()

    def on_modified(self, event):
        if datetime.now() - self.last_modified < timedelta(seconds=1):
            return
        else:
            self.last_modified = datetime.now()
        
        if event.src_path == os.path.join(CWD, 'zones.json'):
            with open(os.path.join(CWD, 'zones.json'), 'rb') as buf:
                zones = json.loads(buf.read())
            shutil.rmtree(os.path.join(CWD, 'zones'), ignore_errors=True)
            main(zones, os.path.join(CWD, 'zones'),
                os.path.join(CWD, 'named.conf.local'))


if __name__ == '__main__':
    PARSER = argparse.ArgumentParser(description='DNS Config Watchdog')
    PARSER.add_argument('--cwd', dest='cwd', action='store_true',
                        required=False,
                        help='Specify CWD rather than /etc/bind/')
    PARSER.add_argument('--remote', dest='remote', action='store',
                        required=False,
                        help='Specify a remote HTTP(S) address' +
                             'to get the zones file from')
    PARSER.add_argument('--watchdog', dest='watchdog', action='store_true',
                        required=False,
                        help='Run as a watchdog service')
    PARSER.add_argument('--skip-refresh', dest='skip_refresh',
                        action='store_true', required=False,
                        help='Skip auto refreshing zones on the DNS server')
    ARGS = PARSER.parse_args()

    if ARGS.watchdog and ARGS.remote:
        print('Error: Cannot start a remote watchdog')
    elif ARGS.watchdog and ARGS.cwd:
        watchdog_cwd()
    elif ARGS.watchdog:
        watchdog()
    else:
        ZONE_DIR = '/etc/bind/zones/'
        CONF_FILE = '/etc/bind/named.conf.local'

        if ARGS.remote:
            if ARGS.remote.lower().startswith('http'):
                # This may trigger a unexpected file inclusion warning on
                # linters but it is safe as it is checked on the line above
                with urllib.request.urlopen(ARGS.remote) as BUF:  # nosec
                    ZONES = json.loads(BUF.read().decode())
            else:
                print('Error: Only HTTP(S) supported for remote files')

        if ARGS.cwd:
            ZONE_DIR = os.path.join(CWD, 'zones')
            CONF_FILE = os.path.join(CWD, 'named.conf.local')

        if ARGS.cwd and not ARGS.remote:
            with open(os.path.join(CWD, 'zones.json'), 'rb') as BUF:
                ZONES = json.loads(BUF.read())

        try:
            ZONES
        except NameError:
            with open('/opt/dns-config-watchdog/zones.json', 'rb') as BUF:
                ZONES = json.loads(BUF.read())

        main(ZONES, ZONE_DIR, CONF_FILE)

        if not ARGS.cwd:
            refresh_dns_zones()
