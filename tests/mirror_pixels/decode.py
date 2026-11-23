"""Read Vita shot BMP pixels, not the in-app model, SSH output or log.

Only accepts the exact 960x544 BGR bitmap and shared SSH 5x7 alphabet.
Ambiguous, nonuniform, foreign or partially drawn glyphs fail closed.
"""
import argparse,ast,json,re,struct
from pathlib import Path
SRC=Path(__file__).resolve().parents[2]/'source'
BG=(12,12,12);FG=(204,204,204); GREEN=(163,255,120) # BGR
X,Y,COLS,ROWS=0,69,80,24
def alphabet():
    mats={}
    for file,tab,f in [('screen.inc','dict','font'),('mirror_font.inc','mirror_extra_dict','mirror_extra_font')]:
        s=(SRC/file).read_text(encoding='utf-8')
        keys=ast.literal_eval(re.search(r'char\s+'+tab+r'\[\]\s*=\s*("(?:\\.|[^"\\])*")',s).group(1))
        vals=re.search(r'uint8_t\s+'+f+r'\[\]\[7\]\s*=\s*\{(.*?)\};',s,re.S).group(1)
        rows=[tuple(map(int,v.split(','))) for v in re.findall(r'\{([0-9,]+)\}',vals)]
        if len(keys)!=len(rows):raise ValueError('font dimensions mismatch')
        for c,m in zip(keys,rows):
            if m in mats:raise ValueError('ambiguous glyphs: %r %r'%(c,mats[m]))
            mats[m]='♥' if c=='\x7f' else c
    mats[(0,)*7]=' '
    return mats
def decode_frame(path,cols=80,rows=24):
    b=Path(path).read_bytes() if not isinstance(path,(bytes,bytearray)) else path
    if len(b)<54 or b[:2]!=b'BM' or struct.unpack_from('<iiHHI',b,18)!=(960,544,1,24,0):
        raise ValueError('expected complete 960x544, bottom-up uncompressed 24bpp Vita shot')
    off=struct.unpack_from('<I',b,10)[0]
    if off<54 or len(b)!=off+960*544*3:raise ValueError('BMP size')
    def color(x,y):
        i=off+3*((543-y)*960+x)
        return tuple(b[i:i+3])
    if sum(color(x,12)==GREEN for x in range(18,650))<5:raise ValueError('missing status header')
    if not 1<=cols<=512 or not 1<=rows<=128:raise ValueError('bind negotiated and clamped PTY geometry')
    m=alphabet()
    def glyph(px,py,scale):
        g=[]
        for dy in range(7):
            bits=0
            for dx in range(5):
                i,j=px+scale*dx,py+scale*dy;p=color(i,j)
                if p not in (BG,FG) or (scale==2 and any(color(a,z)!=p for a,z in ((i+1,j),(i,j+1),(i+1,j+1)))):
                    raise ValueError('nonuniform pixel at (%d,%d)'%(i,j))
                bits=(bits<<1)|(p==FG)
            g.append(bits)
        try:return m[tuple(g)]
        except KeyError:raise ValueError(f'unknown glyph at ({px},{py}): {g}') from None
    heading="VITA AGENT TERMINAL / SHARED SSH"
    if ''.join(glyph(18+12*c,37,2) for c in range(len(heading)))!=heading:raise ValueError('not shared SSH panel')
    # The physical contract is deliberately independent of panel constants.
    footer="DPAD SCROLL/PAN / SQUARE LIVE / TRIANGLE REVIEW / SELECT REVOKES / START EXITS"
    if ''.join(glyph(18+12*c,523,2) for c in range(len(footer)))!=footer:raise ValueError('missing or overwritten footer')
    scale=2;cw,ch=12,20
    return [''.join(glyph(X+c*cw,Y+r*ch,scale) for c in range(min(cols,960//cw))).rstrip()
            for r in range(min(rows,450//ch))]
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('bmp',type=Path);p.add_argument('--json',action='store_true');p.add_argument('--cols',type=int,default=80);p.add_argument('--rows',type=int,default=24);a=p.parse_args()
    rows=decode_frame(a.bmp,cols=a.cols,rows=a.rows)
    print(json.dumps(rows,ensure_ascii=True) if a.json else '\n'.join(rows))
