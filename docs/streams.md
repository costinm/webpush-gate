# Notes on streams and interfaces

## Interface

The stream router can define 2 interfaces:

- Dial(destAddr, initialData, metadata) net.Conn (plus additional interfaces)
- Proxy(in net.Conn, out net.Conn)

## Metadata

Ideal: TCP tunel over H2/H3, using HTTP metadata.

Alternatives:
- SOCKS - broad support, very limited - only destination IP/name and port.
- Postfix XCLIENT - SMTP. Key/value, with NAME, ADDR, PORT, PROTO, LOGIN, DESETADDR, DESTPORT
- HAProxy protocol
    - v1 text
    - v2 binary

```
PROXY TCP4 srcip dstip srcport dstport\r\n

Supports: TCP4, TCP6, max 107 bytes

Header:
\x0D \x0A \x0D \x0A \x00 \x0D \x0A \x51 \x55 \x49 \x54 \x0A
(QUIT)
struct proxy_hdr_v2 {
        uint8_t sig[12];  /* hex 0D 0A 0D 0A 00 0D 0A 51 55 49 54 0A */
        uint8_t ver_cmd;  /* protocol version and command */
        uint8_t fam;      /* protocol family and address */
        uint16_t len;     /* number of following bytes part of the header */
    };

Header, addr type, extra len.
TLV extra:

Issues:
AF_UNIX is byte[108] - could be TLV
The addresses could also be in the TLV
        #define PP2_TYPE_ALPN           0x01
        #define PP2_TYPE_AUTHORITY      0x02
        #define PP2_TYPE_CRC32C         0x03
        #define PP2_TYPE_NOOP           0x04
        #define PP2_TYPE_UNIQUE_ID      0x05
        #define PP2_TYPE_SSL            0x20
        #define PP2_SUBTYPE_SSL_VERSION 0x21
        #define PP2_SUBTYPE_SSL_CN      0x22
        #define PP2_SUBTYPE_SSL_CIPHER  0x23
        #define PP2_SUBTYPE_SSL_SIG_ALG 0x24
        #define PP2_SUBTYPE_SSL_KEY_ALG 0x25
        #define PP2_TYPE_NETNS          0x30
```









