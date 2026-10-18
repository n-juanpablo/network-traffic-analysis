# TCP Three-Way Handshake Analysis

> **Network Traffic Analysis — Investigation 01**

---

## 1. Objective

The objective of this investigation is to analyze how TCP establishes a connection through the **Three-Way Handshake**.

Rather than relying only on the theoretical sequence `SYN → SYN/ACK → ACK`, this investigation reconstructs the handshake directly from packet-level evidence captured in a PCAP file.

The analysis focuses on:

- Identifying the hosts participating in the communication.
- Identifying source and destination ports.
- Understanding the role of the `SYN` and `ACK` flags.
- Analyzing TCP Sequence Numbers and Acknowledgment Numbers.
- Understanding how both endpoints synchronize their sequence spaces.
- Reconstructing the complete TCP connection establishment process using Wireshark.

---

## 2. Environment & Tools

| Item | Details |
|---|---|
| Tool | Wireshark |
| Protocol | TCP |
| Capture format | PCAP |
| Analysis type | Network Traffic Analysis |
| Primary focus | TCP Connection Establishment |

---

# 3. Initial Triage

The first step was to inspect the captured traffic and identify the protocol involved in the communication.

The following Wireshark display filter was applied:

```text
tcp
```

The purpose of this filter was not to alter the PCAP, but to reduce the displayed traffic to TCP packets and make the relevant communication easier to inspect.

After applying the filter, three packets were visible. Their `Info` fields indicated a sequence of:

```text
SYN
SYN, ACK
ACK
```

This immediately suggested that the capture contained a TCP Three-Way Handshake.

### Hosts identified

| Role | IP Address | Port |
|---|---|---:|
| Client | `192.168.1.104` | `49859` |
| Server | `216.18.166.136` | `80` |

The client uses the ephemeral source port `49859` and initiates a connection toward TCP port `80` on the remote host.

### 📸 Screenshot 01 — Initial TCP traffic

**What to capture:**

Show the Wireshark window with:

- The `tcp` display filter.
- The three packets.
- Source and destination addresses.
- Source and destination ports.
- The `SYN`, `SYN, ACK`, and `ACK` sequence visible in the `Info` column.

**Filename:**

```text
01-initial-tcp-filter.png
```

### What this screenshot demonstrates

This screenshot provides the first piece of evidence for the investigation.

Instead of assuming that the PCAP contains a Three-Way Handshake because of its filename or description, the handshake can be identified directly from the packet sequence displayed by Wireshark.

The `Info` column already provides a useful high-level representation of TCP's connection-establishment process:

```text
SYN → SYN/ACK → ACK
```

The following sections examine each packet in greater detail.

---

# 4. Packet 1 — SYN

The first packet is transmitted from:

```text
192.168.1.104:49859
        ↓
216.18.166.136:80
```

The client initiates the TCP connection by setting the `SYN` flag.

## 4.1 TCP Flags

The TCP flags field is:

```text
0x002
```

The relevant flag is:

```text
SYN = Set
ACK = Not Set
```

The `SYN` flag is used to initiate TCP connection establishment.

At this point, the client is not acknowledging previously received TCP data from the server. This is why the acknowledgment number is `0`.

---

## 4.2 Sequence and Acknowledgment Numbers

The packet contains:

| Field | Value |
|---|---:|
| Sequence Number (raw) | `3588415412` |
| Sequence Number (relative) | `0` |
| Acknowledgment Number (raw) | `0` |
| Acknowledgment Number (relative) | `0` |

The distinction between **raw** and **relative** sequence numbers is important when working with Wireshark.

The raw value represents the actual 32-bit sequence number transmitted in the TCP header.

Wireshark can also display relative sequence numbers, which simplify the analysis by presenting the beginning of the TCP conversation as `0`.

In this investigation, both values are useful because the relative values make the sequence easier to understand, while the raw values allow the actual TCP fields to be examined.

---

## 4.3 Why is the ACK number 0?

The first SYN is initiating the communication rather than acknowledging data received from the remote endpoint.

Therefore:

```text
Acknowledgment Number = 0
```

The client is effectively beginning its own sequence space and has not yet received a sequence number from the server that it needs to acknowledge.

---

### 📸 Screenshot 02 — Packet 1 / SYN

**What to capture:**

Select packet 1 and expand:

```text
Transmission Control Protocol
```

Make sure the screenshot clearly shows:

- Source Port: `49859`
- Destination Port: `80`
- Sequence Number
- Acknowledgment Number
- Flags
- `SYN: Set`

**Filename:**

```text
02-packet-1-syn.png
```

### What this screenshot demonstrates

This packet represents the **first step of the TCP handshake**.

The client is essentially initiating the connection and establishing its initial sequence number.

The important point is that TCP is not simply saying "I want to connect." It is also beginning the sequence-number synchronization process that will allow the two endpoints to keep track of the data exchanged during the connection.

---

# 5. Packet 2 — SYN/ACK

The second packet travels in the opposite direction:

```text
216.18.166.136:80
        ↓
192.168.1.104:49859
```

Notice that the source and destination ports have been reversed.

The server responds with two flags:

```text
SYN = Set
ACK = Set
```

This is why the packet is commonly referred to as **SYN/ACK**.

The server is performing two actions simultaneously:

1. Acknowledging the client's SYN.
2. Sending its own SYN to establish its own sequence number.

---

## 5.1 Sequence and Acknowledgment Numbers

The observed values are:

| Field | Value |
|---|---:|
| Sequence Number (raw) | `697411256` |
| Sequence Number (relative) | `0` |
| Acknowledgment Number (raw) | `3588415413` |
| Acknowledgment Number (relative) | `1` |

The relationship between the first two packets is particularly important:

```text
Client Sequence Number
3588415412
       +
       1
       ↓
Server Acknowledgment Number
3588415413
```

The server is therefore acknowledging the client's SYN and indicating that it expects the next sequence number from the client to be `3588415413`.

A key detail is that a SYN consumes one sequence number even though it does not contain application data.

---

## 5.2 Server's Sequence Number

At the same time, the server establishes its own sequence space:

```text
Sequence Number = 697411256
```

This number belongs to the server-to-client direction.

TCP maintains sequence numbers independently in each direction of the connection. Therefore, the server does not continue the client's sequence number. It starts its own sequence space.

This distinction becomes particularly clear when examining the third packet.

---

## 5.3 TCP Flags

The flags field is:

```text
0x012
```

The relevant flags are:

```text
SYN = Set
ACK = Set
```

The hexadecimal value is a representation of the TCP flags field; it is not an arbitrary identifier assigned to the packet.

---

### 📸 Screenshot 03 — Packet 2 / SYN-ACK

**What to capture:**

Select packet 2 and expand:

```text
Transmission Control Protocol
```

Show:

- Source Port: `80`
- Destination Port: `49859`
- Sequence Number
- Acknowledgment Number
- `SYN: Set`
- `ACK: Set`

**Filename:**

```text
03-packet-2-syn-ack.png
```

### What this screenshot demonstrates

This packet is the most informative packet of the handshake because it combines two functions.

The server acknowledges the client's initial sequence number while simultaneously announcing its own sequence number.

This is why the packet contains both `SYN` and `ACK`.

The relationship:

```text
3588415412 + 1 = 3588415413
```

provides direct packet-level evidence that the server is acknowledging the client's SYN.

---

# 6. Packet 3 — ACK

The third packet travels from the client back to the server:

```text
192.168.1.104:49859
        ↓
216.18.166.136:80
```

Unlike the previous packet, this one contains only the `ACK` flag.

The client is now acknowledging the server's SYN.

---

## 6.1 Sequence and Acknowledgment Numbers

The observed values are:

| Field | Value |
|---|---:|
| Sequence Number (raw) | `3588415413` |
| Sequence Number (relative) | `1` |
| Acknowledgment Number (raw) | `697411257` |
| Acknowledgment Number (relative) | `1` |

The client's sequence number is:

```text
3588415413
```

This is the value previously indicated by the server's acknowledgment:

```text
Ack = 3588415413
```

The client is therefore continuing from the sequence number that the server indicated it expected.

The acknowledgment number follows the same logic in the opposite direction:

```text
Server Sequence Number
697411256
       +
       1
       ↓
Client Acknowledgment Number
697411257
```

The client is acknowledging the server's SYN.

---

## 6.2 TCP Flags

The flags field is:

```text
0x010
```

Only:

```text
ACK = Set
```

is present.

Unlike packet 2, the `SYN` flag is no longer set.

---

### 📸 Screenshot 04 — Packet 3 / ACK

**What to capture:**

Select packet 3 and expand:

```text
Transmission Control Protocol
```

Show:

- Source Port: `49859`
- Destination Port: `80`
- Sequence Number
- Acknowledgment Number
- `ACK: Set`
- `SYN: Not Set`

**Filename:**

```text
04-packet-3-ack.png
```

### What this screenshot demonstrates

This packet represents the final step of the Three-Way Handshake.

The client acknowledges the server's SYN, completing the synchronization of both sequence spaces.

At this point, both endpoints have acknowledged the initial SYN received from the other side, and the TCP connection is considered established.

The key evidence is:

```text
Client Seq: 3588415412
Server Ack: 3588415413

Server Seq: 697411256
Client Ack: 697411257
```

Both sequence spaces have therefore been successfully synchronized.

---

# 7. Reconstructing the Three-Way Handshake

The three packets can now be reconstructed into a single sequence:

```text
CLIENT                                      SERVER
192.168.1.104                              216.18.166.136
Port 49859                                 Port 80

     SYN
     Seq = 3588415412
──────────────────────────────────────────────>

                              SYN + ACK
                              Seq = 697411256
                              Ack = 3588415413
<──────────────────────────────────────────────

     ACK
     Seq = 3588415413
     Ack = 697411257
──────────────────────────────────────────────>
```

This reconstruction shows that the handshake is not simply a three-packet exchange.

Each packet has a specific role in synchronizing the sequence numbers used by the two endpoints.

### 📸 Screenshot 05 — Complete handshake

**What to capture:**

Return to the packet list and show all three packets simultaneously.

The screenshot should clearly display:

- Packet number.
- Source.
- Destination.
- Protocol.
- Length.
- `SYN`.
- `SYN, ACK`.
- `ACK`.

**Filename:**

```text
05-three-way-handshake-overview.png
```

### What this screenshot demonstrates

This is the **main evidence screenshot** of the investigation.

A reader should be able to look at it and immediately identify the three stages:

```text
1. SYN
2. SYN/ACK
3. ACK
```

The detailed packet screenshots provide the underlying evidence, while this screenshot provides the overall picture of the connection establishment.

---

# 8. TCP Options Observed

During the analysis, several TCP options were observed within the handshake packets.

| TCP Option | Observed |
|---|---|
| Maximum Segment Size (MSS) | Yes |
| Window Scale | Yes |
| SACK Permitted | Yes |
| Timestamps | Yes |

The observed MSS values were:

```text
Client → Server: 1460 bytes
Server → Client: 1440 bytes
```

These options are negotiated during TCP connection establishment and provide additional parameters that can influence how the connection operates.

They are documented as part of the packet evidence, but detailed analysis of these options is outside the primary scope of this investigation.

This decision keeps the investigation focused on its main objective: understanding and reconstructing the TCP Three-Way Handshake.

### 📸 Screenshot 06 — TCP Options

**Optional.**

If included, show the TCP Options section of packet 1 or packet 2.

The screenshot should make the following visible where applicable:

- MSS
- Window Scale
- SACK Permitted
- Timestamps

**Filename:**

```text
06-tcp-options.png
```

### What this screenshot demonstrates

Although these options are not the main focus of the investigation, their presence demonstrates that the TCP handshake can also be used to negotiate additional connection parameters.

For example, the MSS value communicates the maximum TCP payload size an endpoint is prepared to receive.

Including this screenshot provides additional technical context without expanding the scope of the investigation into a full analysis of TCP options.

---

# 9. Findings

The analysis identified a complete TCP Three-Way Handshake between:

```text
192.168.1.104:49859
```

and:

```text
216.18.166.136:80
```

The observed packet sequence was:

```text
SYN → SYN/ACK → ACK
```

The packet-level evidence demonstrated that:

- `192.168.1.104` initiated the TCP connection.
- `216.18.166.136` responded with `SYN + ACK`.
- The server acknowledged the client's initial sequence number.
- The client acknowledged the server's initial sequence number.
- Each endpoint maintained its own TCP sequence-number space.
- The third `ACK` completed the connection-establishment process.

The sequence-number relationships provide particularly strong evidence:

```text
3588415412 + 1 = 3588415413

697411256 + 1 = 697411257
```

These relationships show how each endpoint acknowledges the other's SYN during the handshake.

---

# 10. Conclusion

This investigation demonstrated how a TCP connection can be reconstructed directly from packet-level evidence.

Rather than treating the Three-Way Handshake as simply:

```text
SYN → SYN/ACK → ACK
```

the packet analysis showed the purpose of each message and how TCP synchronizes sequence numbers between both endpoints.

The investigation demonstrated the following process:

1. The client initiates the connection with a `SYN` and establishes its initial sequence number.
2. The server responds with `SYN + ACK`, acknowledging the client's SYN while establishing its own sequence number.
3. The client responds with `ACK`, acknowledging the server's SYN.
4. Both endpoints are now synchronized and the TCP connection is established.

The analysis also demonstrated how Wireshark's relative sequence numbers can simplify packet analysis while the raw values provide the actual sequence numbers transmitted in the TCP headers.

---

# 11. Wireshark Filter

The primary display filter used during the investigation was:

```text
tcp
```

This filter was used during the initial triage to isolate TCP traffic from the capture.

---

# 12. Key Takeaways

> **The TCP Three-Way Handshake is both a connection-establishment mechanism and a sequence-number synchronization process.**

This investigation reinforced the following concepts:

- TCP connection establishment
- `SYN`, `SYN/ACK`, and `ACK`
- TCP flags
- Sequence Numbers
- Acknowledgment Numbers
- Raw vs. relative sequence numbers
- Independent sequence spaces in each direction
- TCP packet-level analysis with Wireshark
- Evidence-based reconstruction of network communication
