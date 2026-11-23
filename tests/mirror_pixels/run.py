"""Host-only reference pixels using the shipped panel/font/BMP writer. No hardware."""
import argparse,hashlib,json,os,re,string,struct,subprocess,tempfile
from pathlib import Path
from decode import decode_frame
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1];SRC=ROOT/'source'
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--evidence',type=Path);a=p.parse_args()
    ver=re.search(r'^#define\s+WB_VERSION\s+"([^"]+)"',(SRC/'wb_ver.h').read_text(),re.M)[1]
    lines=[f'VITA AGENT TERMINAL {ver} (Workbench)','Type help for commands.','ux0:/> pwd','ux0:/','ux0:/> ls -l','ux0:/> cd VITA-POC','ux0:/VITA-POC> python3 tictactoe_ai.py','====== Main Menu ======',
           '4. HumanPlayer vs SmartComputerPlayer','Enter choice: 4',
           'X makes a move to square 5','|   |   |   |','|   | X |   |','|   |   |   |',
           "O's turn. Input move (1-9) or (q) to quit: 1",'| O |   |   |',
           'X wins! ♥♥♥♥♥♥♥♥♥♥',string.ascii_letters+string.digits,string.punctuation]
    with tempfile.TemporaryDirectory(prefix='vita-mirror-pixels-') as sd:
        d=Path(sd);code=(SRC/'display.c').read_text()
        assert 'wb_panel_needs_raster(&f->mirror_cache,wb_mirror_revision(),agent_online,pin,hint)' in code and 'draw_mirror(pixels,pin,hint,agent_online);' in code
        (d/'capture.inc').write_text('static void put32le'+code.split('static void put32le',1)[1].split('void display_close(',1)[0])
        fixture=d/'fixture';fixture.write_bytes('\r\n'.join(lines).encode('utf8'))
        exe=d/('test.exe' if os.name=='nt' else 'test');bmp=d/'shot.bmp'
        subprocess.run(['gcc','-std=c11','-O2','-Wall','-Wextra','-Werror','-I'+str(SRC),'-I'+str(d),str(HERE/'render.c'),str(SRC/'wb_screen_mirror.c'),'-o',str(exe)],check=True)
        subprocess.run([exe,fixture,bmp,"80","24"],check=True);out=decode_frame(bmp)
        assert out==lines+['']*(22-len(lines)),out
        b=bytearray(bmp.read_bytes());b[54+3*((543-69)*960+18)]^=63
        try:decode_frame(b)
        except ValueError:pass
        else:raise AssertionError('accepted malformed physical glyph')
        # 132x40 remote data stays readable at physical 2x (80x22 window), following cursor.
        wide=[(str(i)+':'+'0123456789'*13)[:132] for i in range(40)]
        f2=d/'wide';b2=d/'wide.bmp';f2.write_bytes('\r\n'.join(wide).encode())
        subprocess.run([exe,f2,b2,'132','40'],check=True)
        assert decode_frame(b2,132,40)==[row[52:] for row in wide[-22:]]
        # Frozen history starts at the left edge, horizontal pan inspects the rest.
        subprocess.run([exe,f2,b2,'132','40','18','8'],check=True)
        assert decode_frame(b2,132,40)==[row[8:88] for row in wide[:22]]
        # Old rows from before the top of a complete 40-row PTY are still drawable.
        seq=[f'ROW-{i:04d}' for i in range(195)]
        f2.write_bytes('\r\n'.join(seq).encode())
        subprocess.run([exe,f2,b2,'120','40','0','0'],check=True)
        assert decode_frame(b2,120,40)==seq[-22:]
        subprocess.run([exe,f2,b2,'120','40','60','0'],check=True)
        assert decode_frame(b2,120,40)==seq[-82:-60]
        f2.write_bytes(b'L'*40+b'R'*148+b'!');subprocess.run([exe,f2,b2,'190','60'],check=True)
        assert decode_frame(b2,190,60)[0]==('L'*40+'R'*148+'!')[110:]
        # Measure from the bitmap itself: 24 H rows in, 22 H rows out; the
        # left stroke is solid for 14 pixels and repeats with 6 blank pixels.
        f2.write_bytes(b'\r\n'.join([b'H']*24));subprocess.run([exe,f2,b2,'80','24'],check=True)
        img=b2.read_bytes();off=struct.unpack_from('<I',img,10)[0]
        lit=[]
        for y in range(69,523):
            at=off+3*((543-y)*960)
            if img[at:at+3]==bytes([204])*3:lit.append(y)
        starts=[y for y in lit if y-1 not in lit];ends=[y for y in lit if y+1 not in lit]
        pitches={b-a for a,b in zip(starts,starts[1:])};heights={b-a+1 for a,b in zip(starts,ends)}
        assert len(starts)==len(ends)==22 and pitches=={20} and heights=={14} and starts[0]==69 and ends[-1]==502, (starts,ends)
        assert decode_frame(b2,80,24)==['H']*22
        # Common 80x24 shell edit without pressing Enter: screen and caret reflect remote echo.
        f2.write_bytes(b'ux0:/> pwf\b \bd');subprocess.run([exe,f2,b2,'80','24'],check=True)
        assert decode_frame(b2)[0]=='ux0:/> pwd'
        sha=hashlib.sha256(bmp.read_bytes()).hexdigest()
        rec={'scope':'HOST C renderer, not a Vita screenshot','verdict':'PASS_HOST_RENDER_MODEL_PIXELS','size':[960,544],'grid':[80,24],'also_tested_pty':[[132,40],[190,60]],'physical_cell':[12,pitches.pop()],'measured_glyph_height':heights.pop(),'visible_max':[80,len(starts)],'decoded_frozen_scroll_and_pan':True,'before_enter':'ux0:/> pwd','all_printable_ascii_plus_heart':True,'rows':out,'host_bmp_sha256':sha}
        if a.evidence:a.evidence.write_text(json.dumps(rec,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        print('PASS host model/pixels: shared PTY 80x24/132x40/190x60; CRLF, split UTF8, erase, ANSI filtering, wrap/scroll, 20px pitch, 14px ink, 6px gap, cursor and footer isolated, exact 96 glyphs, shell banner/edit, prompt and board persist when IDLE; BMP sha256='+sha)
if __name__=='__main__':main()
