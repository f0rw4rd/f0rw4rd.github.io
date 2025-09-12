---
title: "IPv6 in OT: The Forgotten Attack Surface"
date: 2025-09-04 09:00:00 +0100
categories: [Security, OT, Network]
tags: [ipv6, ot, ics, scada, mitm, network-security]
description: "Why IPv6 is lurking in your OT network - dual stack defaults, SLAAC chaos, and why 'just disable it' might be your best security control"
image: /assets/img/ipv6-meme.png
---

You might wonder if I'm being serious with this post. In OT where sometimes IP stacks are completely missing (e.g. PROFIBUS, EtherCAT, IEC 101, IO-Link), why should you care about IPv6?

**IPv6 is probably already running in your OT network**. Not because you planned it, configured it, or even know about it. It's there because modern operating systems enable dual-stack by default, and that Windows HMI or Linux Box in your cabinet you deployed last year is quietly chatting IPv6 on the side.

The security implications? An unmanaged attack surface with exposed services, dual-stack configs that enable DoS attacks via DHCPv6, and potentially vulnerable IPv6 stacks waiting to be exploited. 

## TL;DR

**The Problem**: IPv6 is enabled by default on modern systems, creating an unmanaged attack surface in your OT network. 

**Quick Detection**: 
- `ping -6 -I eth0 ff02::1` - Find all IPv6 devices on segment or  `sudo nmap -6 --script ipv6-multicast-mld-list` - Multicast discovery
- `tcpdump -i eth0 -n ip6` - Monitor IPv6 traffic passively
- `atk6-alive6 eth0` - THC-IPv6 active scanning

**Impact**:
- Exposed IPv6 stack to the network which can contain vulnerabilities like - CVE-2024-38063: Windows IPv6 stack RCE
- IPv6 priority means attackers control routing decisions
- MITM without triggering ARP detection 


**Fix**: Disable IPv6 if not using it. Most OT doesn't need it. CIS Hardening Benchmarks recommend disabling entirely.

## The Dual-Stack Default Dilemma

Here's what most OT engineers overlook: **virtually every modern system runs dual-stack by default**. Your Windows Server 2019 SCADA host? IPv6 enabled. That Linux-based HMI? IPv6 enabled. Even on some modern PLCs. 
But surely it doesn't matter if there's no IPv6 routing? Wrong. Even without routing, IPv6 creates an attack surface in the local segment and if your network is flat and not microsegmented, these segments can be quite large. Because IPv6 has **higher priority than IPv4** in most operating systems when a system can reach a target via both protocols, it prefers IPv6. This means an attacker who controls IPv6 on your local segment essentially controls your traffic. Most OT environments I've assessed have IPv6 enabled on some of the devices. While hardening standards like CIS Benchmarks recommend disabling it, enforcement is challenging across diverse OT assets—and some devices simply don't provide the option. 
Most of the time there's no DHCPv6 server, no router advertisements from legitimate sources—just devices quietly auto-configuring themselves via **SLAAC (Stateless Address Autoconfiguration)**. 

You're also exposing a complex part of the IP stack to the network. There have been some wild vulnerabilities in IPv6 implementations:
- **[CVE-2024-38063](https://www.cve.org/CVERecord?id=CVE-2024-38063)** - Windows IPv6 stack RCE (CVSS 9.8) via malformed packets
- **[CVE-2020-16898](https://www.cve.org/CVERecord?id=CVE-2020-16898)** - "Bad Neighbor" Windows TCP/IP RCE via ICMPv6 Router Advertisement
- **[CVE-2023-4807](https://www.cve.org/CVERecord?id=CVE-2023-4807)** - FreeBSD IPv6 fragment reassembly buffer overflow
- **[CVE-2021-22901](https://www.cve.org/CVERecord?id=CVE-2021-22901)** - curl TELNET stack overflow with IPv6 addresses

Plus, you can achieve MITM attacks on the same segment and bypass ARP spoofing detection, since most network equipment requires a separate feature called **RA Guard** to detect IPv6-based attacks.

## Essential IPv6 Testing Tools

Before diving into discovery and exploitation, you'll need the right tools. For IPv6 assessment, your arsenal should include:

- **[THC-IPv6](https://github.com/vanhauser-thc/thc-ipv6)** - The Swiss Army knife of IPv6 testing
- **Nmap** with IPv6 scripts - For discovery and enumeration
- **[mitm6](https://github.com/dirkjanm/mitm6)** - Specifically for Active Directory attacks via IPv6

```bash
# Install THC-IPv6 toolkit
sudo apt install thc-ipv6
# Note: On Debian, commands are prefixed with 'atk6-'
# Example: alive6 becomes atk6-alive6

# Install mitm6 for AD attacks
pip3 install mitm6
```

## Understanding IPv6 Addresses 

Before we go further, let's decode what these addresses actually mean. Take `fe80::d057:74ff:fe5d:f73f/64`: 

- **fe80::** - Link-local prefix (like 169.254.x.x in IPv4)
- **d057:74ff:fe5d:f73f** - Interface identifier (often derived from the interface MAC)
- **/64** - Subnet size (standard for IPv6 LANs)

The address types you'll encounter in OT:
- **Loopback (::1/128)**: Like 127.0.0.1 in IPv4
- **Unspecified (::/128)**: Like 0.0.0.0 in IPv4
- **Link-local (fe80::/10)**: Every IPv6 interface has one, no configuration needed
- **Unique Local (fc00::/7)**: Like RFC1918 private addresses
 - **fd00::/8** - Locally assigned (what you'll typically use)
 - **fc00::/8** - Centrally assigned (rarely used)
- **Global Unicast (2000::/3)**: Internet-routable
- **Multicast (ff00::/8)**: Replaces broadcast
- **IPv4-mapped (::ffff:0:0/96)**: For dual-stack, e.g., ::ffff:192.168.1.1

How can you tell if an address is MAC-derived or random? Simple: look for the **ff:fe** pattern in the middle. If it's there, it's derived from a MAC address using the modified EUI-64 format. No pattern? It's likely using **Privacy Extensions (RFC 4941)** which generate random, temporary addresses that change periodically to prevent tracking. Windows, macOS, and many Linux distributions enable Privacy Extensions by default, creating multiple IPv6 addresses per interface - one stable for incoming connections and temporary ones for outgoing.

Example ULA address: `fd17:625c:f037:2:a00:27ff:fe60:7052/64`
- **fd** - Locally assigned ULA
- **17:625c:f037** - 40-bit randomly generated Global ID (unique to your site)
- **2** - Subnet ID (this is subnet 2)
- **a00:27ff:fe60:7052** - Interface ID (derived from MAC 08:00:27:60:70:52)


Some OT technologies are using IPv6: Smart meters using G3-PLC communication run IPv6 mesh networks over power lines. Building automation systems leverage 6LoWPAN for wireless sensor networks. These systems were designed IPv6-first, making it mandatory rather than optional. 

## Finding the Hidden IPv6 Assets

So you want to know what's actually running IPv6 in your OT network? Good luck with active scanning—the address space is so vast that brute force approaches are useless. A single /64 subnet has **18,446,744,073,709,551,616** possible addresses. Your scanner will finish sometime after the heat death of the universe, probably shortly after the last Siemens SIMATIC S5 gets decommissioned.

## Passive Discovery Methods

The smartest approach is to start with passive techniques that don't send any packets to the network.

### Listening for IPv6 Traffic

```bash
# Listen for all IPv6 traffic on the local segment
tcpdump -i eth0 -nn ip6

# Passive detection with tcpdump
tcpdump -i eth0 -n 'ip6 and not host ::1' -w ipv6-traffic.pcap

# Monitor for Router Advertisements
tcpdump -i eth0 -n 'icmp6 and ip6[40] == 134'

# Capture Neighbor Discovery traffic
tcpdump -i eth0 -n 'icmp6 and (ip6[40] == 135 or ip6[40] == 136)'
```

Devices announce themselves through **Duplicate Address Detection (DAD)** when they boot, sending Neighbor Solicitations from the unspecified address (::). This is gold for passive discovery.

```bash
# Use THC-IPv6 to passively discover addresses
sudo atk6-passive_discovery6 eth0

# Detect new IPv6 devices as they join
sudo atk6-detect-new-ip6 eth0
```

### Mining Protocols for IPv6 Addresses

Some protocols leak configuration data including IPv6 addresses. **LLDP (Link Layer Discovery Protocol)** is particularly chatty. Vendors like Hirschmann and Cisco have their own discovery protocols that often leak IPv6 addresses when configured. You can passively capture these with tcpdump:

```bash
# Capture LLDP frames passively
tcpdump -i eth0 -s 1500 -c 1 'ether proto 0x88cc'

# Decode LLDP information
tcpdump -i eth0 -vv ether proto 0x88cc
```

### MAC to IPv6 Calculation

If you know the MAC address (from ARP tables, switch CAM tables, or asset inventory), you can calculate potential IPv6 addresses. Most devices don't use privacy extensions, so they generate predictable **EUI-64** addresses based on their MAC:

```bash
# Python one-liner: MAC 08:00:27:60:70:52 -> fe80::0a00:27ff:fe60:7052
python -c "m='08:00:27:60:70:52'.replace(':',''); print(f'fe80::{int(m[0:2],16)^2:02x}{m[2:4]}:{m[4:6]}ff:fe{m[6:8]}:{m[8:10]}{m[10:12]}')"

# Calculate multiple addresses from MAC list
for mac in $(arp -n | awk '{print $3}' | grep :); do
  python -c "m='$mac'.replace(':',''); print(f'{mac} -> fe80::{int(m[0:2],16)^2:02x}{m[2:4]}:{m[4:6]}ff:fe{m[6:8]}:{m[8:10]}{m[10:12]}')"
done
```


## Active Scanning Methods

Active scanning for IPv6 requires different strategies than IPv4 due to the vast address space. Here are the techniques that actually work:

### DNS Enumeration

Systems often register IPv6 addresses in DNS, especially in Active Directory environments:

```bash
# Query for AAAA records (IPv6 addresses)
dig AAAA server.domain.local

# Reverse lookup for IPv4 that might reveal IPv6
host 192.168.1.100

# DNS zone transfer (if allowed) to find IPv6 records
dig @192.168.1.53 company.local AXFR | grep AAAA

# Use dnsrecon for comprehensive enumeration
dnsrecon -d company.local -t std,rvl,srv
```

### Windows RPC Enumeration

On Windows systems with RPC access and no credentials (tested with Windows 10) and the IPv4, you can get non-SLAAC IPv6 addresses with Impacket by using the _ServerAlive2_ RPC method. Source: https://github.com/mubix/IOXIDResolver

```bash
# pip install impacket
python3 -c "from impacket.dcerpc.v5 import transport,dcomrt;t=transport.DCERPCTransportFactory('ncacn_ip_tcp:169.254.167.172').get_dce_rpc();t.connect();print([b['aNetworkAddr'] for b in dcomrt.IObjectExporter(t).ServerAlive2()])"
['DESKTOP-RACCOONS-AT-WORK\x00', '169.254.167.172\x00', '169.254.152.128\x00', 'dead:beef:f01d:af01:daf0:1daf:1da:f01d\x00']
```

If you have credentials, you can use WMI or tools like CME/NXC to go for SMB/RPC for example. 

```bash
 nxc smb 169.254.167.172 -u user -p password --interfaces # thx @Sixtus for the feedback!
```

### Scanning via Multicast

When you don't have specific targets, multicast addresses let you discover all IPv6 devices:

**Common IPv6 Multicast Addresses:**
- `ff02::1` - All nodes on local link (every IPv6 device)
- `ff02::2` - All routers
- `ff02::c` - SSDP (Simple Service Discovery Protocol)
- `ff02::fb` - mDNSv6
- `ff02::1:2` - All DHCP servers and relay agents
- `ff02::1:ff00:0` - Solicited-node address

For a complete list, see [IANA IPv6 Multicast Addresses](https://www.iana.org/assignments/ipv6-multicast-addresses/).



```bash
# Best discovery method - tries multiple multicast addresses
# use -e to the set interface
sudo nmap -6 --script ipv6-multicast-mld-list

# Ping all nodes and extract unique IPs
ping -6 -I eth0 ff02::1 -c3 | grep "bytes from" | cut -d " " -f4 | cut -d "%" -f1 | sort -u

# Alternative for older systems  
ping6 -I eth0 ff02::1

# Ping all routers (discover default gateways)
ping -6 -I eth0 ff02::2

# THC-IPv6's comprehensive alive scanning (Debian prefix: atk6-)
sudo atk6-alive6 eth0
# With increased wait time for slow responders
sudo atk6-alive6 -W -i eth0

# Passively discover IPv6 addresses on the network
sudo atk6-passive_discovery6 eth0

# Detect new IPv6 addresses joining the network
sudo atk6-detect-new-ip6 eth0

# Dump all local routers and their information
sudo atk6-dump_router6 eth0

# Dump all DHCPv6 servers
sudo atk6-dump_dhcp6 eth0

# Send node information queries
sudo atk6-node_query6 eth0 fe80::1

# Scan for IPv6 node information with nmap
sudo nmap -6 --script ipv6-node-info.nse -n --packet-trace fe80::854f:891c:a724:fad6
```

Example with nmap: 

```bash
sudo nmap -6 --script ipv6-multicast-mld-list -e enp0s9
Starting Nmap 7.97 ( https://nmap.org ) at 2025-09-12 16:15 +0200
Pre-scan script results:
| ipv6-multicast-mld-list: 
|   fe80::9fcb:ca:43b0:c1ab: 
|     device: enp0s9
|     mac: 08:00:27:6a:66:0c
|     multicast_ips: 
|       ff02::1:ffb0:c1ab         (NDP Solicited-node)
|       ff02::1:3                 (Link-local Multicast Name Resolution)
|       ff02::fb                  (mDNSv6)
|_      ff02::c                   (SSDP)
WARNING: No targets were specified, so 0 hosts scanned.
Nmap done: 0 IP addresses (0 hosts up) scanned in 10.22 seconds
```

![IPv6 Multicast Network Capture](/assets/img/ipv6-multicast-capture.png)

### Targeted Scanning from Known Information

If you have MAC addresses or IPv4 addresses, you can target specific IPv6 addresses:

```bash
# Convert MAC to EUI-64 and scan
# Example: MAC 08:00:27:60:70:52 -> fe80::0a00:27ff:fe60:7052
python -c "m='08:00:27:60:70:52'.replace(':',''); print(f'fe80::{int(m[0:2],16)^2:02x}{m[2:4]}:{m[4:6]}ff:fe{m[6:8]}:{m[8:10]}{m[10:12]}')" | xargs -I {} nmap -6 -sn {}%eth0

# THC-IPv6's inverse neighbor discovery (Debian prefix: atk6-)
sudo atk6-inverse_lookup6 eth0 08:00:27:60:70:52

# Convert MAC/IPv4 to IPv6 address
atk6-address6 08:00:27:60:70:52
atk6-address6 192.168.1.1

# Map IPv4 hosts to potential IPv6 addresses and scan
nmap -6 -n --script targets-ipv6-map4to6 --script-args newtargets,targets-ipv6-map4to6.IPv4Hosts={192.168.1.0/24},targets-ipv6-subnet={fe80::/64} -sP

# Scan specific calculated addresses
nmap -6 -sn fe80::0a00:27ff:fe60:7052%eth0
```


## Working with IPv6

Once you've identified IPv6 assets, connecting to them requires understanding the syntax differences from IPv4. Standard tools work with IPv6, but link-local addresses need interface specification:

```bash
# Linux - View IPv6 addresses on all interfaces
ip -6 addr show

# Add IPv6 address to interface
ip -6 addr add 2001:db8::1/64 dev eth0

# Show IPv6 routes
ip -6 route show

# Add static IPv6 route
ip -6 route add 2001:db8::/32 via fe80::1 dev eth0

# Show IPv6 neighbors (like ARP for IPv4)
ip -6 neigh show

# Ping link-local address (requires %interface)
ping fe80::c641:1eff:fe83:199f%eth0

# HTTP with IPv6 (brackets required for addresses)
curl -6 "http://[fe80::a00:27ff:fed3:72ef%eth1]:8000/"
curl "http://[2001:db8::1]:8080/api/status"

# SSH to IPv6 address
ssh user@fe80::a00:27ff:fed3:72ef%eth0
ssh -6 user@2001:db8::1

# Ncat with IPv6 (nc may not support IPv6)
ncat -6 fe80::1%eth0 502
ncat -6 2001:db8::1 80

# Nmap IPv6 scanning
nmap -6 fe80::1%eth0
nmap -6 2001:db8::/64
```

```powershell
# Windows PowerShell - View IPv6 configuration
Get-NetIPAddress -AddressFamily IPv6

# View IPv6 addresses with more detail
Get-NetAdapter | Get-NetIPAddress -AddressFamily IPv6

# Add IPv6 address to interface
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 2001:db8::1 -PrefixLength 64

# Show IPv6 routes
Get-NetRoute -AddressFamily IPv6

# Add static IPv6 route  
New-NetRoute -DestinationPrefix "2001:db8::/32" -NextHop "fe80::1" -InterfaceAlias "Ethernet"

# Show IPv6 neighbor cache
Get-NetNeighbor -AddressFamily IPv6

# Test IPv6 connectivity
Test-NetConnection -ComputerName 2001:db8::1
Test-NetConnection -ComputerName fe80::1%12  # %12 is interface index

# HTTP requests with IPv6 (PowerShell 5.1+)
Invoke-WebRequest -Uri "http://[2001:db8::1]:8080/api/status"
Invoke-RestMethod -Uri "http://[fe80::a00:27ff:fe14:8307%12]:8000/"

# Using curl.exe on Windows 10/11
curl.exe -6 "http://[2001:db8::1]:8080/api/status"

# View interface indexes for link-local addresses
Get-NetAdapter | Select-Object Name, InterfaceIndex, Status

# Resolve IPv6 address
Resolve-DnsName server.domain.local -Type AAAA

# Flush IPv6 neighbor cache
Remove-NetNeighbor -AddressFamily IPv6 -Confirm:$false
```

### Bridging IPv4 Tools to IPv6 Targets

Many tools were designed for IPv4 and haven't been updated for IPv6. Engineering workstations, protocol analyzers and other software often can't connect to IPv6 addresses directly. The workaround? Create local IPv4-to-IPv6 proxies that make IPv6 targets appear as IPv4 services. This works most of the time, except for services that do broadcast discovery and do not allow a direct IPv4 connection. 

```bash
# Install proxy tools
sudo apt install 6tunnel socat

# socat - TCP relay from IPv4 to IPv6 (note the quotes!)
socat TCP4-LISTEN:8080,fork,reuseaddr "TCP6:[2001:db8::1]:80"
# For link-local addresses with interface
socat TCP4-LISTEN:502,fork,reuseaddr "TCP6:[fe80::854f:891c:a724:fad6]:502,interface=eth0"

# 6tunnel - lightweight IPv6 to IPv4 proxy
# Basic syntax: 6tunnel [-d] [-v] localport ipv6address remoteport
6tunnel -d -v 4444 fe80::854f:891c:a724:fad6%eth0 22
# For global addresses
6tunnel 8080 2001:db8::1 80

# proxychains with IPv6 SOCKS proxy
# Edit /etc/proxychains.conf: socks5 ::1 1080
proxychains4 ./legacy-tool target.com

# SSH tunnel for IPv6 access (note brackets and quotes!)
ssh user@jumphost -L "4444:[fe80::854f:891c:a724:fad6%eth0]:22"
# For global addresses
ssh user@jumphost -L "5002:[2001:db8::1]:502"
# Now connect to localhost:4444 or localhost:5002 with IPv4 tools
```

## Defense against IPv6

The best defense against IPv6 attacks in OT? Disable IPv6 if you're not using it. However, Microsoft does not recommend disabling it for Windows without proper consideration, because some features will no longer work.
According to [Microsoft documentation](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/configure-ipv6-in-windows), these features break:
* HomeGroup (file sharing)
* DirectAccess (remote access)
* Remote Assistance
* Windows Mail
* Exchange Server functionality
* Active Directory replication (Server 2019/2022) 
* ... ?

Interestingly, CIS Benchmarks for L2 recommend to turn it off anyway, prioritizing security over functionality. If you are unsure and cannot test whether your systems work without IPv6, you have some alternatives:

### Windows Configuration

```powershell
# Option 1: Prefer IPv4 over IPv6
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v DisabledComponents /t REG_DWORD /d 32 /f

# Option 2: Block IPv6 at the firewall instead of disabling it
# This keeps the protocol active but prevents external IPv6 traffic
New-NetFirewallRule -DisplayName "Block IPv6" -Direction Inbound -Protocol ICMPv6 -Action Block
New-NetFirewallRule -DisplayName "Block IPv6" -Direction Inbound -Protocol TCP -LocalPort Any -RemoteAddress ::/0 -Action Block
New-NetFirewallRule -DisplayName "Block IPv6" -Direction Inbound -Protocol UDP -LocalPort Any -RemoteAddress ::/0 -Action Block

# Option 3: Disable it
# Disable IPv6 on all adapters
Set-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6 -Enabled $false

# Or via registry (requires reboot)
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" `
    -Name "DisabledComponents" -Value 0xFF -PropertyType DWord
```

### Linux Configuration

```bash
# Option 1: Prefer IPv4 over IPv6 (without disabling IPv6)
echo "precedence ::ffff:0:0/96 100" >> /etc/gai.conf

# Alternative: Modify preference via sysctl
echo "net.ipv6.conf.all.disable_ipv6 = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6 = 0" >> /etc/sysctl.conf
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.forwarding = 0" >> /etc/sysctl.conf

# Option 2: Block IPv6 at the firewall (using nftables)
nft add table ip6 filter
nft add chain ip6 filter input { type filter hook input priority 0 \; policy drop \; }
nft add chain ip6 filter forward { type filter hook forward priority 0 \; policy drop \; }
nft add chain ip6 filter output { type filter hook output priority 0 \; policy drop \; }
nft add rule ip6 filter input iif lo accept
nft add rule ip6 filter output oif lo accept

# Option 3: Disable IPv6 completely
# Temporary disable
sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv6.conf.default.disable_ipv6=1

# Permanent disable
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
```

## Conclusion

IPv6 represents an unmanaged attack surface in OT environments. While the protocol itself offers legitimate use cases, its default-enabled status on modern systems creates security risks that are often overlooked in industrial networks.
**Recommendation**: Check your networks for IPv6, implement appropriate mitigations, and add IPv6 to your security assessment checklist.

## Bonus: Detecting IPv6 Sniffers

Here's something that shouldn't work but does: detecting promiscuous mode hosts on IPv6 networks. The `atk6-detect_sniffer6` tool (from THC-IPv6) exploits how systems in promiscuous mode handle malformed packets:

```bash
# Detect hosts in promiscuous mode (Debian prefix: atk6-)
sudo atk6-detect_sniffer6 eth0

# Example output:
# Sending sniffer detection packets to ff02::1
#  Sniffing host detected: fe80::be24:11ff:fe9e:8906
#  Sniffing host detected: fe80::e343:960a:3dec:8d4f
```

**How it works:**
1. Sends special ICMP6 echo requests to multicast address `ff02::1`
2. Includes both normal packets and packets with invalid destination headers (`NXT_INVALID`)  
3. Normal systems drop packets with invalid headers
4. Systems in promiscuous mode often process them anyway and respond
5. The tool detects responses containing its signature "thcsniff"

This shouldn't work because promiscuous mode is supposed to be passive, but many network stacks process malformed packets differently when sniffing, creating this detection opportunity.

## Bonus Bonus : IPv6 as a Covert Channel

A colleague and I once joked about using cryptography to generate addresses and hide assets in the vast IPv6 space. Cryptographically Generated Addresses (CGAs) use this principle legitimately—they generate IPv6 addresses from cryptographic hashes of public keys as defined in [RFC 3972](https://www.rfc-editor.org/rfc/rfc3972). Only someone with the private key can prove ownership of that address. But here's where it gets interesting: you could create entire networks of addresses that appear random but follow a cryptographic sequence only you can generate.
