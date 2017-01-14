# Free Wifi

This short tutorial describes a few methods for gaining access to the Internet, [a basic human right](https://en.wikipedia.org/wiki/Right_to_Internet_access#2011:_UN_Special_Rapporteur_report), from public wireless networks.

## Preparation

Make sure you do this step *before* you are stuck without Internet access.

```
$ git clone https://github.com/kylemcdonald/FreeWifi
$ cd FreeWifi && pip install -r requirements.txt
```

## How to get additional time

If you had free internet access but your time has run out, the first thing to try is open an incognito/private window. This will temporarily clear any cookies that may have been used for tracking how much time you spent, and might allow you to log into the wireless portal again.

Unfotunately, most systems track MAC addresses instead of cookies. This means you need to pick a new MAC address to get additional time. The `spoof-mac` command line utility makes this easy with `sudo spoof-mac randomize Wi-Fi`. If doesn't work, try running `spoof-mac list --wifi` to check what the name of your wireless device is first. After running that command, try logging into the wireless portal again. When you're done using the Internet, run `sudo spoof-mac reset Wi-Fi` to reset your MAC address.

## How to get free access

If the network is open, but you can't get access for some reason, you can also try spoofing the MAC address of a device that is already using the network. To the router, your device and the other device will look like one device. This can cause some minor problems if they interrupt each other, but for light browsing it usually works out fine.

To find the MAC addresses of other devices using the network, first you need to connect to the network. You don't need to have Internet access, just a connection. Then run the command `sudo chmod o+r /dev/bpf*` to make sure you can sniff wireless data. Then run the command `python wifi-users.py`. You should see something like this after 10 seconds:

```
Collecting 1000 packets, looking for SSID (74:4c:17:ac:b3:13)...
Total of 5 user(s):
27:35:96:a8:66:7f	6359 bytes
36:fe:83:9c:35:eb	9605 bytes
65:01:3c:cc:20:e8	17306 bytes
8c:6f:11:2c:f0:ee	20515 bytes
0a:4f:b2:b8:e8:56	71541 bytes
```

If there isn't much traffic on the network, it might take longer. Finally, we want to spoof one of these MAC addresses. For example: `sudo spoof-mac set 0a:4f:b2:b8:e8:56 Wi-Fi`. After running that command, try to access the Internet. If your Internet connection drops out while using this MAC address, try disconnecting and reconnecting to the wireless network.

### How it works

`wifi-users.py` uses `tcpdump` to collect wireless packets. Then we look through these packets for any hints of the MAC address (BSSID) of our wireless network. Finally, we look for data packets that mention a network BSSID, or the network gateway, and add up the length of the packet to a total for that user's MAC. We sort the user's MAC by the total data and take the top 10.