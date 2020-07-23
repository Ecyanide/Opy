import copy
from struct import*
from CONSTRUCTOR import (
    sm_shifts, sm_chain0 ,num_rounds, sm_rcon, sm_S, sm_Si,
    sm_U1, sm_U2, sm_U3, sm_U4,
    sm_T1, sm_T2, sm_T3, sm_T4, sm_T5, sm_T6, sm_T7, sm_T8
)

DEFAULT_blockSize=16
MAX_blockSize=32 
MAX_ROUNDS=14
MAX_KC=8
MAX_BC=8

#//Expand a user-supplied key material into a session key.
#// key        - The 128/192/256-bit user-key to use.
#// chain      - initial chain block for CBC and CFB modes.
#// keylength  - 16, 24 or 32 bytes
#// blockSize  - The block size in bytes of this Rijndael (16, 24 or 32 bytes).

class Rijndael:
    def __init__(self):
        self.m_bKeyInit = False
        self.m_chain = None
        self.m_kd = None
        self.m_ke = None

    
    def MakeKey(self, key, chain, blockSize) -> bytes:
        keylength = len(key)
        if not key: raise ValueError("Incorrect key length")
        if keylength and blockSize not in num_rounds: raise ValueError("Incorrect block or key length")

        
        rounds = num_rounds[len(key)][blockSize]
        self.block_size = blockSize
        if chain:
            self.m_chain = unpack('c'*blockSize, chain )
        BC = blockSize // 4
        m_ke = [[0] * BC for _ in range(rounds + 1)]
  
        m_kd = [[0] * BC for _ in range(rounds + 1)]
        round_key_count = (rounds + 1) * BC
        KC = len(key) // 4

 
        tk = []
        for i in range(0, KC):
            tk.append((ord(key[i * 4:i * 4 + 1]) << 24) | (ord(key[i * 4 + 1:i * 4 + 1 + 1]) << 16) |
                      (ord(key[i * 4 + 2: i * 4 + 2 + 1]) << 8) | ord(key[i * 4 + 3:i * 4 + 3 + 1]))

     
        t = 0
        j = 0
        while j < KC and t < round_key_count:
            m_ke[t // BC][t % BC] = tk[j]
            m_kd[rounds - (t // BC)][t % BC] = tk[j]
            j += 1
            t += 1
        r_con_pointer = 0
        while t < round_key_count:
          
            tt = tk[KC - 1]
            tk[0] ^= (sm_S[(tt >> 16) & 0xFF] & 0xFF) << 24 ^ \
                     (sm_S[(tt >> 8) & 0xFF] & 0xFF) << 16 ^ \
                     (sm_S[tt & 0xFF] & 0xFF) << 8 ^ \
                     (sm_S[(tt >> 24) & 0xFF] & 0xFF) ^ \
                     (sm_rcon[r_con_pointer] & 0xFF) << 24
            r_con_pointer += 1
            if KC != 8:
                for i in range(1, KC):
                    tk[i] ^= tk[i - 1]
            else:
                for i in range(1, KC // 2):
                    tk[i] ^= tk[i - 1]
                tt = tk[KC // 2 - 1]
                tk[KC // 2] ^= (sm_S[tt & 0xFF] & 0xFF) ^ \
                                (sm_S[(tt >> 8) & 0xFF] & 0xFF) << 8 ^ \
                                (sm_S[(tt >> 16) & 0xFF] & 0xFF) << 16 ^ \
                                (sm_S[(tt >> 24) & 0xFF] & 0xFF) << 24
                for i in range(KC // 2 + 1, KC):
                    tk[i] ^= tk[i - 1]
         
            j = 0
            while j < KC and t < round_key_count:
                m_ke[t // BC][t % BC] = tk[j]
                m_kd[rounds - (t // BC)][t % BC] = tk[j]
                j += 1
                t += 1
    
        for r in range(1, rounds):
            for j in range(BC):
                tt = m_kd[r][j]
                m_kd[r][j] = (
                    sm_U1[(tt >> 24) & 0xFF] ^
                    sm_U2[(tt >> 16) & 0xFF] ^
                    sm_U3[(tt >> 8) & 0xFF] ^
                    sm_U4[tt & 0xFF]
                )
        self.m_ke = m_ke
        self.m_kd = m_kd
        self.m_bKeyInit = True

    def EncryptBlock(self, source):
        if len(source) != self.block_size:
            raise ValueError(
                'Wrong block length, expected %s got %s' % (
                    str(self.block_size),
                    str(len(source))
                )
            )

        KE = self.m_ke

        BC = self.block_size // 4
        rounds = len(KE) - 1
        if BC == 4:
            SC = 0
        elif BC == 6:
            SC = 1
        else:
            SC = 2
        s1 = sm_shifts[SC][1][0]
        s2 = sm_shifts[SC][2][0]
        s3 = sm_shifts[SC][3][0]
        a = [0] * BC
       
        t = []
    
        for i in range(BC):
            t.append((ord(source[i * 4: i * 4 + 1]) << 24 |
                      ord(source[i * 4 + 1: i * 4 + 1 + 1]) << 16 |
                      ord(source[i * 4 + 2: i * 4 + 2 + 1]) << 8 |
                      ord(source[i * 4 + 3: i * 4 + 3 + 1])) ^ KE[0][i])
       
        for r in range(1, rounds):
            for i in range(BC):
                a[i] = (sm_T1[(t[i] >> 24) & 0xFF] ^
                        sm_T2[(t[(i + s1) % BC] >> 16) & 0xFF] ^
                        sm_T3[(t[(i + s2) % BC] >> 8) & 0xFF] ^
                        sm_T4[t[(i + s3) % BC] & 0xFF]) ^ KE[r][i]
            t = copy.copy(a)
       
        result = []
        for i in range(BC):
            tt = KE[rounds][i]
            result.append((sm_S[(t[i] >> 24) & 0xFF] ^ (tt >> 24)) & 0xFF)
            result.append((sm_S[(t[(i + s1) % BC] >> 16) & 0xFF] ^ (tt >> 16)) & 0xFF)
            result.append((sm_S[(t[(i + s2) % BC] >> 8) & 0xFF] ^ (tt >> 8)) & 0xFF)
            result.append((sm_S[t[(i + s3) % BC] & 0xFF] ^ tt) & 0xFF)
        out = bytes()
        for xx in result:
            out += bytes([xx])
        return out
    
    def DecryptBlock(self, cipher):
        if len(cipher) != self.block_size:
            raise ValueError(
                'wrong block length, expected %s got %s' % (
                    str(self.block_size),
                    str(len(cipher))
                )
            )

        KD = self.m_kd
        BC = self.block_size // 4
        rounds = len(KD) - 1
        if BC == 4:
            SC = 0
        elif BC == 6:
            SC = 1
        else:
            SC = 2
        s1 = sm_shifts[SC][1][1]
        s2 = sm_shifts[SC][2][1]
        s3 = sm_shifts[SC][3][1]
        a = [0] * BC
  
        t = [0] * BC
    
        for i in range(BC):
            t[i] = (ord(cipher[i * 4: i * 4 + 1]) << 24 |
                    ord(cipher[i * 4 + 1: i * 4 + 1 + 1]) << 16 |
                    ord(cipher[i * 4 + 2: i * 4 + 2 + 1]) << 8 |
                    ord(cipher[i * 4 + 3: i * 4 + 3 + 1])) ^ KD[0][i]
    
        for r in range(1, rounds):
            for i in range(BC):
                a[i] = (sm_T5[(t[i] >> 24) & 0xFF] ^
                        sm_T6[(t[(i + s1) % BC] >> 16) & 0xFF] ^
                        sm_T7[(t[(i + s2) % BC] >> 8) & 0xFF] ^
                        sm_T8[t[(i + s3) % BC] & 0xFF]) ^ KD[r][i]
            t = copy.copy(a)
     
        result = []
        for i in range(BC):
            tt = KD[rounds][i]
            result.append((sm_Si[(t[i] >> 24) & 0xFF] ^ (tt >> 24)) & 0xFF)
            result.append((sm_Si[(t[(i + s1) % BC] >> 16) & 0xFF] ^ (tt >> 16)) & 0xFF)
            result.append((sm_Si[(t[(i + s2) % BC] >> 8) & 0xFF] ^ (tt >> 8)) & 0xFF)
            result.append((sm_Si[t[(i + s3) % BC] & 0xFF] ^ tt) & 0xFF)
        out = bytes()
        for xx in result:
            out += bytes([xx])
        return out
    
    def Encrypt(self, In, iMode=None):
        if not self.m_bKeyInit: raise ValueError("Object not Initialized")
        if not self.block_size: raise ValueError("Data not multiple of Block Siz")
        if not iMode: #ECB mode, not using the Chain
            return self.EncryptBlock(In)
