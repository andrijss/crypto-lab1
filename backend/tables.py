"""External DES tables: structural validation, including legal E repetitions."""
import json
from pathlib import Path

def load(path):
    d = json.loads(Path(path).read_text())
    specs = {'IP':(64,64), 'IP_INV':(64,64), 'PC1':(56,64), 'PC2':(48,56), 'E':(48,32), 'P':(32,32), 'SHIFTS':(16,2)}
    if set(d) != set(specs)|{'S_BOXES'}: raise ValueError('Incomplete DES table set')
    for name,(size,limit) in specs.items():
        a=d[name]
        if not isinstance(a,list) or len(a)!=size or any(type(v)!=int or not 1<=v<=limit for v in a): raise ValueError('Invalid DES table: '+name)
        if name not in ('E','SHIFTS') and len(set(a))!=size: raise ValueError('Duplicate entries in '+name)
    if set(d['PC1']) != set(range(1,65))-set(range(8,65,8)): raise ValueError('PC1: invalid parity bit positions')
    if any(d['IP_INV'][v-1]!=i+1 for i,v in enumerate(d['IP'])): raise ValueError('IP and IP_INV are not inverses')
    if d['E'] != [((4*i+j-1)%32)+1 for i in range(8) for j in range(6)]: raise ValueError('Invalid E expansion')
    if d['SHIFTS'] != [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]: raise ValueError('Invalid rotation schedule')
    if len(d['S_BOXES'])!=8: raise ValueError('Expected 8 S-boxes')
    for box in d['S_BOXES']:
        if len(box)!=4 or any(len(row)!=16 or any(type(x)!=int for x in row) or set(row)!=set(range(16)) for row in box): raise ValueError('Invalid S-box')
    return d

globals().update(load(Path(__file__).with_name('des_tables.json')))
