## Rijndael
requires python 3.6+ (experimentally supports python 3.5)

## Block cipher mode of operation
| Common modes | Chain | Status |
| --- | --- | --- |
| [ECB](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB)) | No | Yes |
| [CBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC))| Yes | Waiting |
| [CFB ](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_feedback_(CFB))| Yes | Waiting |

**Example**: **key chain**  from [reconstruct_master_login(tRO)](https://github.com/OpenKore/openkore/blob/0d835885b9aaed5a3041be731ba2c6c0c4b624ff/src/Network/Send/tRO.pm#L85)
```py
from struct import*
key = pack('32B',*(0x06, 0xA9, 0x21, 0x40, 0x36, 0xB8, 0xA1, 0x5B, 0x51, 0x2E, 0x03, 0xD5, 0x34, 0x12, 0x00, 0x06, 0x06, 0xA9, 0x21, 0x40, 0x36, 0xB8, 0xA1, 0x5B, 0x51, 0x2E, 0x03, 0xD5, 0x34, 0x12, 0x00, 0x06))
chain  = pack('32B',*(0x3D, 0xAF, 0xBA, 0x42, 0x9D, 0x9E, 0xB4, 0x30, 0xB4, 0x22, 0xDA, 0x80, 0x2C, 0x9F, 0xAC, 0x41, 0x3D, 0xAF, 0xBA, 0x42, 0x9D, 0x9E, 0xB4, 0x30, 0xB4, 0x22, 0xDA, 0x80, 0x2C, 0x9F, 0xAC, 0x41))

```


**Encrypt**
```py

from Rijndael import *
In = pack('32s', b'thisbytes_password')
rijndael = _Rijndael()
rijndael.MakeKey(key, chain, 32)
password_rijndael = rijndael.Encrypt(in, iMode=None)
```
