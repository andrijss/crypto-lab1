import secrets
from . import des


def key_check(key, algorithm='DES'):
    if algorithm != 'DES':
        raise ValueError('Unknown algorithm')
    if len(key) != 8:
        raise ValueError('DES keys must contain 8 bytes')
    if any(byte.bit_count() % 2 != 1 for byte in key):
        raise ValueError('DES: key must have odd parity')


def generate(algorithm='DES', bits=64):
    if algorithm != 'DES' or bits != 64:
        raise ValueError('DES requires a 64-bit key including parity bits')
    return bytes((byte & 254) | ((byte & 254).bit_count() % 2 ^ 1)
                 for byte in secrets.token_bytes(8))


class DES:
    block_size=8
    def __init__(self,key):self.keys=des.generate_round_keys(key)
    def run(self,b,keys):
        if len(b)!=8:raise ValueError('DES: expected an 8-byte block')
        p=des.permute(int.from_bytes(b,'big'),des.constants.IP,64);l,r=p>>32,p&0xffffffff
        for k in keys:l,r=r,l^des.feistel(r,k)
        return des.permute((r<<32)|l,des.constants.IP_INV,64).to_bytes(8,'big')
    def encrypt(self,b):return self.run(b,self.keys)
    def decrypt(self,b):return self.run(b,self.keys[::-1])

def xor(a,b):return bytes(x^y for x,y in zip(a,b))
def pad(b,size,scheme):
    n=size-len(b)%size
    return b+(bytes(n-1)+bytes([n]) if scheme=='X923' else bytes([n])*n)
def unpad(b,size,scheme):
    n=b[-1] if b else 0
    if not 1<=n<=size or b[-n:]!=(bytes(n-1)+bytes([n]) if scheme=='X923' else bytes([n])*n):raise ValueError('Invalid padding or incorrect key')
    return b[:-n]

class Mode:
    def __init__(self, key, algorithm, mode, iv, backend='own', decrypt=False):
        key_check(key, algorithm)
        if mode not in ('ECB', 'CBC'):
            raise ValueError('Unsupported mode')
        if backend not in ('own', 'library'):
            raise ValueError('Unknown implementation')
        self.size = 8
        self.mode = mode
        self.dec = decrypt
        self.prev = iv
        self.lib = None
        if len(iv) != (0 if mode == 'ECB' else 8):
            raise ValueError('Invalid IV length')
        if backend == 'library':
            from Crypto.Cipher import DES as LibraryDES
            self.lib = LibraryDES.new(key, LibraryDES.MODE_ECB if mode == 'ECB'
                                      else LibraryDES.MODE_CBC,
                                      **({'iv': iv} if mode == 'CBC' else {}))
        else:
            self.c = DES(key)

    def update(self, data):
        if len(data) % self.size:
            raise ValueError('DES data must contain complete 8-byte blocks')
        if self.lib:
            return self.lib.decrypt(data) if self.dec else self.lib.encrypt(data)
        output = bytearray()
        for offset in range(0, len(data), self.size):
            block = data[offset:offset + self.size]
            if self.mode == 'ECB':
                result = self.c.decrypt(block) if self.dec else self.c.encrypt(block)
            elif self.dec:
                result = xor(self.c.decrypt(block), self.prev)
                self.prev = block
            else:
                result = self.c.encrypt(xor(block, self.prev))
                self.prev = result
            output.extend(result)
        return bytes(output)
