# Sniff Wifi

## Find Devices Connected to a WiFi Access Point with Python

Clients (devices) conected to a Wifi access point can be detected quite easily via packets/data frames passing between both devices. Tools such as airodump aide this and here we can dig a little deeper with Python.

### Monitor Mode with airmon-ng

Activate your Wireless Card Monitor mode

```console
user@home:~$ airmon-ng start wlan1
```

We use the sniff package from scapy to scan for nearby packets and output the result.

