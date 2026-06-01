---
title: "IEC 61850: A Security Primer for Substation Protocols"
date: 2026-04-16 14:00:00 +0100
categories: [ICS Security, Protocols]
tags: [iec61850, goose, mms, substation, energy, protocol-analysis]
description: "What MMS, GOOSE, and SV actually do inside a substation, and how to poke them from Python with pyiec61850-ng."
image:
  path: /assets/img/iec61850-meme.jpg
  alt: Ancient Chinese proverb
---

Energy is by far my favourite industry to work in. One of the protocol suites I'd always wanted to look at properly is **IEC 61850** and its MMS, GOOSE and SV pieces. This post is the writeup.

IEC 61850 is sold as the modern substation protocol suite. What's actually deployed is a mix. **DNP3** is still dominant in North America, **IEC 60870-5-101/104** across Europe, and **Modbus** keeps showing up in places nobody has touched for fifteen years. IEC 61850 tends to appear on the protection ("Schutz") side, on products like **ABB's 800M** (usually inside an ABB 800xA DCS) or **Siemens SIPROTEC** IEDs.

When protection fails, you get videos like [this one](https://www.youtube.com/watch?v=nyjCrP38ICc). The TenneT [Flevoland incident report](https://tennet-drupal.s3.eu-central-1.amazonaws.com/default/2023-02/23-2534%20DNV%20Publieke%20samenvatting%20onderzoeksrapport%20Flevoland%202%20september%202022_0.pdf) is also a good read on what a bad day in a transmission substation looks like.

**Intelligent Electronic Devices (IEDs)** are what's doing the work. A typical IED covers some mix of:

- **Protection**: spot faults (overcurrent, voltage, frequency) and trip a breaker in milliseconds
- **Control**: operate breakers, switches and other primary equipment
- **Monitoring**: measure voltage, current, power, frequency
- **Recording**: capture fault records and disturbance data
- **Communication**: talk to other IEDs and to SCADA

Tree falls on a line. An **overcurrent protection IED** picks up the fault current, fires a **GOOSE** message to trip the upstream breaker, logs it locally, and reports it up to the control centre over **MMS**. GOOSE is supposed to land in under 4 ms and **SV** under 250 μs, which is what drives the network and bus design.

## Attacks on IEC 61850

I couldn't find any active MMS or GOOSE protocol exploits catalogued in MITRE ATT&CK. Most documented activity in this space is against IEDs directly; the protocols usually only show up as the way in.

**Industroyer / CRASHOVERRIDE** is the common reference. Sandworm (attributed to GRU Unit 74455) used it against the **Pivnichna** ("North") 330 kV transmission substation just outside Kyiv late on December 17, 2016, cutting roughly a fifth of the city's power for just over an hour. The framework shipped payload DLLs for IEC 60870-5-101 (`101.dll`), IEC 60870-5-104 (`104.dll`), OPC DA, and **IEC 61850** (`61850.dll`). Anton Cherepanov's [ESET writeup](https://www.welivesecurity.com/2017/06/12/industroyer-biggest-threat-industrial-control-systems-since-stuxnet/) and the [MITRE ATT&CK S0604 entry](https://attack.mitre.org/software/S0604/) are the go-to references.

The 61850 module did nothing exotic. Find TCP/102 hosts, send MMS `GetNameList` to enumerate logical nodes, grep for `CSW` (Control Switch) to find breaker controls, then drive them. MMS was the recon and control path.

## Protocol Architecture

A substation in 61850 terms is three levels:

- **Station** — SCADA/HMI, where operators sit
- **Bay** — protection and control IEDs
- **Process** — **Merging Units (MUs)** and sensors digitising raw electrical measurements

Two buses glue it together: the **station bus** (bay ↔ station) and the **process bus** (process ↔ bay). Three protocols run across them: **MMS** (point-to-point), **GOOSE** (multicast), **SV** (sampled values).

MMS itself is the application layer. It reaches TCP port 102 via the ISO stack: **TPKT** (RFC 1006) wraps **COTP** (ISO 8073 Class 0), which carries ISO Session + Presentation + MMS (ISO 9506), everything ASN.1 BER encoded. Port 102 is also where S7comm lives, sharing the TPKT/COTP framing with MMS, so it's worth filtering on TPKT payloads when you're staring at pcaps from an industrial network.

```
IEC 61850 Protocol Architecture
┌─────────────────────────────────────────────────────────────┐
│                    IEC 61850 Suite                          │
├─────────────────────────────────────────────────────────────┤
│ Application │ ACSI (Abstract Communication Service)         │
│ Layer       │ ├─ Logical Nodes (XCBR, MMXU, PTOC...)        │
│             │ ├─ Data Objects & Attributes                  │
│             │ └─ Service Models (Report, Control, Log)      │
├─────────────────────────────────────────────────────────────┤
│ Protocol    │ ┌─────────┬─────────┬─────────┐               │
│ Mapping     │ │   MMS   │  GOOSE  │   SV    │               │
│             │ │(Client- │(Publish-│(Sample  │               │
│             │ │Server)  │Subscribe│Values)  │               │
│             │ └─────────┴─────────┴─────────┘               │
├─────────────────────────────────────────────────────────────┤
│ Transport   │ TCP/102   │ Ethernet │ Ethernet               │
│ Layer       │ Routable  │ Layer 2  │ Layer 2                │
│             │ 1-10s     │ 0x88B8   │ 0x88BA                 │
│             │ latency   │ <4ms     │ <250μs                 │
└─────────────────────────────────────────────────────────────┘

Communication Patterns:
┌─────────────────────────────────────────────────────────────┐
│ MMS: SCADA ←─────────→ IED (Configuration, Control)         │
│              TCP/IP Network (Station Bus)                   │
├─────────────────────────────────────────────────────────────┤
│ GOOSE: IED ══════════⇒ IED (Protection Signals)             │
│               Layer 2 Multicast (Station Bus)               │
├─────────────────────────────────────────────────────────────┤
│ SV: Merging Unit ═══⇒ Protection IEDs (CT/VT Data)          │
│               High-Speed Layer 2 (Process Bus)              │
└─────────────────────────────────────────────────────────────┘
```

**MMS** (Manufacturing Message Specification) is vertical client/server. SCADA and engineering talk to IEDs this way. **GOOSE** (Generic Object Oriented Substation Events) is horizontal peer-to-peer between IEDs, for protection signalling. **SV** (Sampled Values) is digitised analog from merging units onto the process bus.

**Merging Units** convert analog CT/VT signals into time-stamped digital samples and publish them on the process bus. From the MU forward everything is digital, behind it everything is analog.

### MMS and the VMD Model

MMS treats each IED as a **Virtual Manufacturing Device (VMD)**: a filesystem of data points. A VMD has **Logical Devices** (directories), which hold **Logical Nodes** (files), which hold the actual data attributes. One physical IED can host several logical devices, so a single box might run separate LDs for protection, measurement and control.

### Substation Configuration Language (SCL)

**SCL** is the XML format that describes IEDs and the substation they live in. Engineering tools produce it, IEDs get their slice as configuration. The three common variants:

- **ICD** (IED Capability Description): data sheet for a single IED. What it can do, its data model, its services.
- **SCD** (Substation Configuration Description): the whole substation. Every IED, every link, every subscription.
- **CID** (Configured IED Description): the final config for a specific IED.

If you come across an SCD during an assessment, keep it. It's the whole data model and addressing plan in one file, and it saves days of enumeration later.

MMS maps 61850's object model onto ISO 9506 services. The VMD looks like this:

```
VMD Structure
├─ Domains (Logical Devices)
│  └─ IED1LD0
│     ├─ Named Variables (Logical Nodes)
│     │  ├─ XCBR1 (Circuit Breaker)
│     │  │  ├─ Pos (Position)
│     │  │  ├─ OpCnt (Operation Counter)
│     │  │  └─ BlkOpn (Block Opening)
│     │  ├─ MMXU1 (Measurements)
│     │  │  ├─ PhV (Phase Voltages)
│     │  │  ├─ A (Current)
│     │  │  └─ Hz (Frequency)
│     │  └─ PTOC1 (Overcurrent Protection)
│     │     ├─ Op (Operate)
│     │     └─ Str (Start)
│     ├─ Named Variable Lists (Datasets)
│     ├─ Journals (Event Logs)
│     └─ Files (Configurations, Reports)
```

MMS object types inside the VMD:

- **Domains**: top-level containers, usually one per logical device
- **Named Variables**: individual addressable data points
- **Variable Lists**: grouped variables for batch reads
- **Journals**: event logs and historical data
- **Files**: configuration, disturbance records, sometimes firmware

MMS references are `$`-separated:

```
IED1LD0/XCBR1$ST$Pos$stVal
└─┬──┘ └──┬┘ └┬┘ └┬┘ └──┬─┘
  │      │   │   │     └── Data Attribute (status value, here an enum)
  │      │   │   └──────── Data Object (breaker Position)
  │      │   └──────────── Functional Constraint (ST=Status, MX=Measurands, CO=Control, CF=Config)
  │      └──────────────── Logical Node (XCBR = Circuit Breaker, instance 1)
  └─────────────────────── Logical Device
```

Another one: `IED1LD0/MMXU1$MX$PhV$phsA$cVal$mag$f`, phase A voltage magnitude as a float. The ACSI dotted form most client APIs take is `IED1LD0/MMXU1.PhV.phsA.cVal.mag.f`.

```
MMS Service Mapping
┌────────────────────────────────────────────┐
│ IEC 61850 Service    │ MMS Service         │
├────────────────────────────────────────────┤
│ GetServerDirectory   │ GetNameList         │
│ GetLogicalDeviceDir  │ GetNameList         │
│ GetDataValues        │ Read                │
│ SetDataValues        │ Write               │
│ GetDataSetValues     │ Read (named var)    │
│ Report               │ InfoReport          │
│ Control              │ Write + Read        │
│ GetFile              │ FileOpen/Read/Close │
└────────────────────────────────────────────┘
```

## Where's the Security?

Security for IEC 61850 is supposed to come from the **IEC 62351** series. Adoption is poor.

- **IEC 62351-3**: TLS for MMS, certificate auth, encrypted control. Requires you to actually run a CA and manage certificates.
- **IEC 62351-6**: signatures on GOOSE and SV, plus multicast key distribution.
- **IEC 62351-7**: network and system management, SNMP security, IDS guidance.

MMS has an ACSE password mechanism. It's rarely enabled, and when it is the password is sent cleartext. Authorization is coarse, so read access usually gets you most of what's interesting, and the file service hands out configuration, disturbance records and sometimes firmware to anyone who can open a connection. The "security" in the field is usually that the substation LAN is segregated and nobody has plugged in.

## Poking It from Python

The usual option when you meet 61850 on an engagement is to use someone else's library rather than re-implement MMS. The de-facto C library is [libiec61850](https://github.com/mz-automation/libiec61850) from mz-automation and it covers MMS, GOOSE and SV. Java has **IEC61850bean** from [beanit.com](https://www.beanit.com/iec-61850/), an Apache-licensed MMS client/server implementation (no GOOSE/SV in that library itself). For Python there were a few bindings on top of libiec61850, but none of them shipped recent wheels, kept up with upstream, or handled memory cleanly. So I built one.

> **[pyiec61850-ng](https://github.com/f0rw4rd/pyiec61850-ng)** — Python bindings for libiec61850, as a wheel: `pip install pyiec61850-ng`. `MMSClient` handles the LinkedList/MmsValue cleanup you normally do by hand, `ControlClient` handles Select-Before-Operate, and `GooseSubscriber` does layer-2 work.
{: .prompt-tip }

All the snippets below hit the test server from `examples/docker-compose.yml` (libiec61850's `server_example_basic_io`, port 10102):

```bash
cd pyiec61850-ng/examples
docker compose up -d
```

### 1. Connect and identify

Cheapest recon first: ask the IED who it is. [Claroty Team82 have a nice writeup](https://claroty.com/team82/research/mms-under-the-microscope-examining-the-security-of-a-power-automation-standard) on fingerprinting MMS stacks by their supported services and released a dedicated tool for it ([MMS-Stack-Detector](https://github.com/claroty/MMS-Stack-Detector)). Before any of that, just grab the identity string:

```python
from pyiec61850.mms import MMSClient

with MMSClient() as client:
    client.connect("localhost", 10102)
    identity = client.get_server_identity()
    print(f"{identity.vendor} {identity.model} rev {identity.revision}")
```

Against the libiec61850 demo:

```
libiec61850.com MZA server on Linux rev 1.5.3
```

The underlying ISO 9506 `Identify` service is unauthenticated on most real IEDs and normally returns vendor, model, firmware revision, sometimes serial. Enough to line up public CVEs.

### 2. Walk the data model

Next job is enumerating the VMD. Logical devices, logical nodes, data objects. `GetNameList` under the hood.

```python
with MMSClient() as client:
    client.connect("localhost", 10102)

    for ld in client.get_logical_devices():
        print(f"LD: {ld}")
        for ln in client.get_logical_nodes(ld):
            print(f"  LN: {ln}")
            for do in client.get_data_objects(ld, ln):
                print(f"    DO: {ld}/{ln}.{do}")
```

On `basic_io` you get `simpleIOGenericIO/GGIO1`, `LLN0`, `MMXU1`, and so on. That's the menu for the next step.

### 3. Read values

```python
value = client.read_value("simpleIOGenericIO/MMXU1.TotW.mag.f")
print(value)   # e.g. 1234.5
```

On a real IED the same call gets you phase voltages, currents, breaker state, counters, and, if you want to know how the device is set up, configuration parameters under the `CF` functional constraint.

### 4. Write / control

Writes go through the `Write` service. Anything that moves primary plant (breakers, switches) usually goes through **Select-Before-Operate (SBO)**: you select the object first, operate second. It's there so a stray write doesn't trip a 400 kV breaker. Both patterns:

```python
from pyiec61850.mms import MMSClient, ControlClient

with MMSClient() as client:
    client.connect("localhost", 10102)
    ctrl = ControlClient(client)

    # What control model does this object use?
    model = ctrl.get_control_model("simpleIOGenericIO/CSWI1.Pos")
    print(model)   # direct-with-normal-security, sbo-with-enhanced-security, ...

    # Direct operate
    ctrl.direct_operate("simpleIOGenericIO/CSWI1.Pos", True)

    # Select-before-operate
    ctrl.select("simpleIOGenericIO/CSWI1.Pos")
    ctrl.operate("simpleIOGenericIO/CSWI1.Pos", False)
```

### 5. File service

The MMS file service is normally the fastest way to anything worth reading. COMTRADE disturbance records, CID/SCD configs, and occasionally firmware. File listing needs a callback that isn't fully wrapped yet, but file download works against the raw bindings:

```python
import pyiec61850.pyiec61850 as pyiec61850

conn = pyiec61850.IedConnection_create()
pyiec61850.IedConnection_connect(conn, "localhost", 10102)

err = pyiec61850.MmsError_create()
mms = pyiec61850.IedConnection_getMmsConnection(conn)
pyiec61850.MmsConnection_downloadFile(mms, err, "/COMTRADE/fault_001.cfg", "fault_001.cfg")
```

## GOOSE

GOOSE messages are Ethernet multicast so you need layer-2 reach. A protection IED on a trip publishes roughly this:

```
GOOSE Message Structure:
┌─────────────────────────────────────┐
│ Ethernet Header (Dst: 01:0C:CD:...) │
├─────────────────────────────────────┤
│ GOOSE PDU                           │
│ ├─ gocbRef: "PROT_IED/LLN0$GO$..."  │
│ ├─ timeAllowedtoLive: 1000ms        │
│ ├─ datSet: "PROT_IED/TRIP_DATA"     │
│ ├─ allData:                         │
│ │   ├─ [0] Trip: TRUE               │
│ │   └─ [1] Zone: 1                  │
│ └─ stNum: 42, sqNum: 1              │
└─────────────────────────────────────┘
```

No handshake, no polling. Every IED on the subnet sees the trip immediately. For sniffing, there's a raw-socket subscriber in the library (needs root):

```python
from pyiec61850.goose import GooseSubscriber

def on_msg(msg):
    print(f"stNum={msg.st_num} sqNum={msg.sq_num} valid={msg.is_valid} values={msg.values}")

with GooseSubscriber("eth0", "simpleIOGenericIO/LLN0$GO$gcbAnalogValues") as sub:
    sub.set_listener(on_msg)
    sub.start()
    while True: pass
```

Watch `stNum` and `sqNum`. `stNum` bumps on every state change, `sqNum` resets and counts retransmissions while the state holds. Without 62351-6 nothing is signing these. If you're on the bus, spoofing one is easy.

## Wrap-up

Substation IEDs have 20-30 year lifecycles. Whatever you poke at today will still be on the network for a long time. Edition 3 and IEC 62351 look fine on paper but in the field it's still plaintext MMS on TCP/102 with little or no authentication, and GOOSE/SV on a shared LAN with nothing signing them.

Practical checklist on an engagement: enumerate the VMD, read widely, avoid writes unless you know exactly what you're touching, and grab an SCD if one is within reach. If you want to do this from Python, [pyiec61850-ng](https://github.com/f0rw4rd/pyiec61850-ng) is on PyPI and the `examples/` folder has Docker demos for everything above.
