https://en.wikipedia.org/wiki/ASN.1#Example_encoded_in_DER
https://learn.microsoft.com/de-de/windows/win32/seccertenroll/about-der-encoding-of-asn-1-types

https://stackoverflow.com/a/13104466

- publicExponent: 65537 (it is convention that all RSA public keys use 65537 as their exponent)
- modulus: hex:`DC 67 FA F4 9E F2 72 1D 45 2C B4 80 79 06 A0 94 27 50 8209 DD 67 CE 57 B8 6C 4A 4F 40 9F D2 D1 69 FB 995D 85 0C 07 A1 F9 47 1B 56 16 6E F6 7F B9 CF 2A 58 36 37 99 29 AA 4F A8 12 E8 4F C7 82 2B 9D 72 2A 9C DE 6F C2 EE 12 6D CF F0 F2 B8 C4 DD 7C 5C 1A C8 17 51 A9 AC DF 08 22 04 9D 2B D7 F9 4B 09 DE 9A EB 5C 51 1A D8 F8 F9 56 9E F8 FB 37 9B 3F D3 74 65 24 0D FF 34 75 57 A4 F5 BF 55`

The DER ASN.1 encoding of this public key is:

```
30 81 89          ;SEQUENCE (0x89 bytes = 137 bytes)
|  02 81 81       ;INTEGER (0x81 bytes = 129 bytes)
|  |  00          ;leading zero of INTEGER
|  |  DC 67 FA
|  |  F4 9E F2 72 1D 45 2C B4  80 79 06 A0 94 27 50 82
|  |  09 DD 67 CE 57 B8 6C 4A  4F 40 9F D2 D1 69 FB 99
|  |  5D 85 0C 07 A1 F9 47 1B  56 16 6E F6 7F B9 CF 2A
|  |  58 36 37 99 29 AA 4F A8  12 E8 4F C7 82 2B 9D 72
|  |  2A 9C DE 6F C2 EE 12 6D  CF F0 F2 B8 C4 DD 7C 5C
|  |  1A C8 17 51 A9 AC DF 08  22 04 9D 2B D7 F9 4B 09
|  |  DE 9A EB 5C 51 1A D8 F8  F9 56 9E F8 FB 37 9B 3F
|  |  D3 74 65 24 0D FF 34 75  57 A4 F5 BF 55
|  02 03          ;INTEGER (0x03 = 3 bytes)
|  |  01 00 01    ;hex for 65537. see it?
```

If you take that entire above DER ASN.1 encoded modulus+exponent:

`30 81 89 02 81 81 00 DC 67 FA F4 9E F2 72 1D 45 2C B4 80 79 06 A0 94 27 50 82 09 DD 67 CE 57 B8 6C 4A 4F 40 9F D2 D1 69 FB 99 5D 85 0C 07 A1 F9 47 1B 56 16 6E F6 7F B9 CF 2A 58 36 37 99 29 AA 4F A8 12 E8 4F C7 82 2B 9D 72 2A 9C DE 6F C2 EE 12 6D CF F0 F2 B8 C4 DD 7C 5C 1A C8 17 51 A9 AC DF 08 22 04 9D 2B D7 F9 4B 09 DE 9A EB 5C 51 1A D8 F8 F9 56 9E F8 FB 37 9B 3F D3 74 65 24 0D FF 34 75 57 A4 F5 BF 55 02 03 01 00 01`

and you PEM encode it (i.e. base64):

`MIGJAoGBANxn+vSe8nIdRSy0gHkGoJQnUIIJ3WfOV7hsSk9An9LRafuZXYUMB6H5RxtWFm72f7nPKlg2N5kpqk+oEuhPx4IrnXIqnN5vwu4Sbc/w8rjE3XxcGsgXUams3wgiBJ0r1/lLCd6a61xRGtj4+Vae+Ps3mz/TdGUkDf80dVek9b9VAgMBAAE=`

It's a convention to wrap that base64 encoded data in:

```
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBANxn+vSe8nIdRSy0gHkGoJQnUIIJ3WfOV7hsSk9An9LRafuZXY
UMB6H5RxtWFm72f7nPKlg2N5kpqk+oEuhPx4IrnXIqnN5vwu4Sbc/w8rjE
3XxcGsgXUams3wgiBJ0r1/lLCd6a61xRGtj4+Vae+Ps3mz/TdGUkDf80dV
ek9b9VAgMBAAE=
-----END RSA PUBLIC KEY-----
```

And that's how you get an have a PEM DER ASN.1 PKCS#1 RSA Public key.

Fileextension: `*.pem`
