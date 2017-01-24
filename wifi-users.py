from __future__ import print_function
import subprocess, re, sys, argparse, os
from collections import defaultdict

import netifaces
from netaddr import EUI, mac_unix_expanded
from wireless import Wireless
from tqdm import tqdm

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def run_process(cmd, err=False):
    err_pipe = subprocess.STDOUT if err else open(os.devnull, 'w')
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=err_pipe)
    while(True):
        retcode = p.poll()
        line = p.stdout.readline()
        yield line
        if(retcode is not None):
            break

def main(args):
    parser = argparse.ArgumentParser(
        description='Find active users on the current wireless network.')
    parser.add_argument('-p', '--packets',
        default=1000,
        type=int,
        help='How many packets to capture.')
    parser.add_argument('-r', '--results',
        default=None,
        type=int,
        help='How many results to show.')
    args = parser.parse_args()

    try:
        wireless = Wireless()
        ssid = wireless.current()
        if ssid is None:
            eprint('No SSID is currently available. Connect to the network first.')
            return
        eprint('SSID: {}'.format(ssid))
    except:
        eprint('Couldn\'t get current wireless SSID.')
        raise

    network_macs = set()
    try:
        gw = netifaces.gateways()['default'][netifaces.AF_INET]
        iface = gw[1]
        gw_arp = subprocess.check_output(['arp', '-n', str(gw[0])])
        gw_arp = gw_arp.decode('utf-8')
        gw_mac = EUI(re.search(' at (.+) on ', gw_arp).group(1))
        gw_mac.dialect = mac_unix_expanded
        network_macs.add(gw_mac)
        eprint('Gateway: {}'.format(gw_mac))
    except KeyError:
        eprint('No gateway is available: {}'.format(netifaces.gateways()))
        return
    except:
        eprint('Error getting gateway mac address.')

    bssid_re = re.compile(' BSSID:(\S+) ')
    da_re = re.compile(' DA:(\S+) ')
    sa_re = re.compile(' SA:(\S+) ')

    mac_re = re.compile('(SA|DA|BSSID):(([\dA-F]{2}:){5}[\dA-F]{2})', re.I)
    length_re = re.compile(' length (\d+)')
    client_macs = set()
    data_totals = defaultdict(int)

    cmd = 'tcpdump -i {} -Ile -c {}'.format(iface, args.packets).split()
    try:
        bar_format = '{n_fmt}/{total_fmt} {bar} {remaining}'
        for line in tqdm(run_process(cmd), total=args.packets, bar_format=bar_format):
            line = line.decode('utf-8')

            # find BSSID for SSID
            if ssid in line:
                bssid_matches = bssid_re.search(line)
                if bssid_matches:
                    bssid = bssid_matches.group(1)
                    if not 'Broadcast' in bssid:
                        network_macs.add(EUI(bssid))

            # count data packets
            length_match = length_re.search(line)
            if length_match:
                length = int(length_match.group(1))
                mac_matches = mac_re.findall(line)
                if mac_matches:
                    macs = set([EUI(match[1]) for match in mac_matches])
                    leftover = macs - network_macs
                    if len(leftover) < len(macs):
                        for mac in leftover:
                            data_totals[mac] += length
                            client_macs.add(mac)

    except subprocess.CalledProcessError:
        eprint('Error collecting packets.')
        raise
    except KeyboardInterrupt:
        pass

    print()

    totals_sorted = sorted(data_totals.items(), key=lambda x: x[1], reverse=True)

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