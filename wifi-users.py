from __future__ import print_function
import subprocess
import re
import sys
import argparse
import os
from collections import defaultdict

import netifaces
from netaddr import EUI, mac_unix_expanded
from wireless import Wireless
from tqdm import tqdm

NO_SSID = 'No SSID is currently available. Connect to the network first.'
NO_WIRELESS = 'Error getting wireless interface.'
NO_GATEWAY_MAC = 'Error getting gateway MAC address.'

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def run_process(cmd, err=False):
    err_pipe = subprocess.STDOUT if err else open(os.devnull, 'w')
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=err_pipe)
    while True:
        retcode = p.poll()
        line = p.stdout.readline()
        yield line
        if retcode is not None:
            break


def main(args):
    parser = argparse.ArgumentParser(
        description='Find active users on the current wireless network.')
    parser.add_argument('-p', '--packets',
                        default=1000,
                        type=int,
                        help='How many packets to capture.')
    parser.add_argument('-i', '--interface',
                        default=None,
                        type=str,
                        help='Which wireless interface to use.')
    parser.add_argument('-s', '--ssid',
                        default=None,
                        type=str,
                        help='Which SSID to use.')
    parser.add_argument('-r', '--results',
                        default=None,
                        type=int,
                        help='How many results to show.')
    args = parser.parse_args()

    try:
        if args.interface:
            iface = args.interface
        else:
            wireless = Wireless()
            ifaces = wireless.interfaces()
            eprint('Available interfaces: {}'.format(', '.join(ifaces)))
            iface = ifaces[-1]
        eprint('Interface: {}'.format(iface))

        if args.ssid:
            ssid = args.ssid
        else:
            wireless = Wireless()
            ssid = wireless.current()
            if ssid is None:
                eprint(NO_SSID)
                return
        eprint('SSID: {}'.format(ssid))
    except:
        eprint(NO_WIRELESS)
        raise

    mac_re_str = '([\dA-F]{2}:){5}[\dA-F]{2}'
    mac_re = re.compile(mac_re_str, re.I)
    network_macs = set()
    try:
        gws = netifaces.gateways()[netifaces.AF_INET]
        gw_ifaces = ', '.join([gw[1] for gw in gws])
        eprint('Available gateways: {}'.format(gw_ifaces))
        gw_ip = next(gw[0] for gw in gws if gw[1] == iface)
        eprint('Gateway IP: {}'.format(gw_ip))
        gw_arp = subprocess.check_output(['arp', '-n', str(gw_ip)])
        gw_arp = gw_arp.decode('utf-8')
        gw_mac = EUI(mac_re.search(gw_arp).group(0))
        gw_mac.dialect = mac_unix_expanded
        network_macs.add(gw_mac)
        eprint('Gateway MAC: {}'.format(gw_mac))
    except StopIteration:
        eprint('No gateway for {}'.format(iface))
    except KeyError:
        eprint('No gateways available: {}'.format(netifaces.gateways()))
    except:
        eprint(NO_GATEWAY_MAC)

    bssid_re = re.compile(' BSSID:(\S+) ')

    tcpdump_mac_re = re.compile('(SA|DA|BSSID):(' + mac_re_str + ')', re.I)
    length_re = re.compile(' length (\d+)')
    client_macs = set()
    data_totals = defaultdict(int)

    cmd = 'tcpdump -i {} -Ile -c {} -s 0'.format(iface, args.packets).split()
    try:
        bar_format = '{n_fmt}/{total_fmt} {bar} {remaining}'
        progress = tqdm(run_process(cmd),
                        total=args.packets,
                        bar_format=bar_format)
        for line in progress:
            line = line.decode('utf-8')

            # find BSSID for SSID
            if ssid in line:
                bssid_matches = bssid_re.search(line)
                if bssid_matches:
                    bssid = bssid_matches.group(1)
                    if 'Broadcast' not in bssid:
                        network_macs.add(EUI(bssid))

            # count data packets
            length_match = length_re.search(line)
            if length_match:
                length = int(length_match.group(1))
                mac_matches = tcpdump_mac_re.findall(line)
                if mac_matches:
                    macs = set([EUI(match[1]) for match in mac_matches])
                    leftover = macs - network_macs
                    if len(leftover) < len(macs):
                        for mac in leftover:
                            data_totals[mac] += length
                            client_macs.add(mac)

        if progress.n < progress.total:
            eprint('Sniffing finished early.')

    except subprocess.CalledProcessError:
        eprint('Error collecting packets.')
        raise
    except KeyboardInterrupt:
        pass

    totals_sorted = sorted(data_totals.items(),
                           key=lambda x: x[1],
                           reverse=True)

    eprint('Total of {} user(s)'.format(len(totals_sorted)))

    for mac, total in reversed(totals_sorted[:args.results]):
        mac.dialect = mac_unix_expanded
        if total > 0:
            print('{}\t{} bytes'.format(mac, total))


if __name__ == '__main__':
    from sys import argv

    try:
        main(argv)
    except KeyboardInterrupt:
        pass
    sys.exit()
