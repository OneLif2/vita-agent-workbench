"""Generate/check the checked-in ASCII atlas and license without network or installed fonts.
Run: python tools/gen_jetbrains_bitmap.py --check    (or --write to regenerate)
"""
import argparse, hashlib, json
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

ROOT=Path(__file__).resolve().parents[1]
A=ROOT/"tools"/"font_assets"; OUT=ROOT/"source"
F_SHA="a0bf60ef0f83c5ed4d7a75d45838548b1f6873372dfac88f71804491898d138f"
L_SHA="30f0c136e3c88e422d0791acd97238870f9054a9729bc34cf2ff0d4ed8cac4ad"
W,H=8,14

def read_checked(file,sha):
    b=file.read_bytes()
    if hashlib.sha256(b).hexdigest()!=sha:raise ValueError("wrong upstream file: "+str(file))
    return b

def generated():
    ttf=A/"JetBrainsMono-Regular.ttf"
    read_checked(ttf,F_SHA)
    lic=read_checked(A/"OFL.txt",L_SHA).decode("ascii")
    # Preserve exact downloaded license bytes including CR if upstream adds one.
    notice="""/* Generated from the unmodified upstream OFL.txt; see tools/font_assets/README.md. */
#ifndef WB_JETBRAINS_LICENSE_H
#define WB_JETBRAINS_LICENSE_H
static const char wb_jb_license[] =
"""+''.join("    "+json.dumps(x)+"\n" for x in lic.splitlines(keepends=True))+"    ;\n#endif\n"
    font=ImageFont.truetype(ttf,12,layout_engine=ImageFont.Layout.BASIC)
    if font.getname()!=("JetBrains Mono","Regular"):raise ValueError("font metadata mismatch")
    rows=[]
    for c in range(32,127):
        # Draw on a larger guarded bitmap; don't silently shear accents/descenders.
        im=Image.new("L",(32,40)); ImageDraw.Draw(im).text((10,20),chr(c),font=font,anchor="ls",fill=255)
        im=im.point(lambda a: 255 if a>=104 else 0); box=im.getbbox()
        # origin 10,9 -> baseline 11 in the target cell.
        if box and not(10<=box[0]<box[2]<=18 and 9<=box[1]<box[3]<=23):raise ValueError(f"clipping U+{c:04X}")
        glyph=tuple(sum((1<<(W-x-1)) for x in range(W) if im.getpixel((10+x,9+y))) for y in range(H))
        if bool(any(glyph))!=(c!=32):raise ValueError(f"empty nonspace U+{c:04X}")
        rows.append(glyph)
    if len(set(rows))!=95:raise ValueError("two printable ASCII glyphs are indistinguishable")
    # A Workbench-owned heart, NOT a glyph or control character from the upstream font.
    rows.append((0,0,0,0,0x66,0xff,0xff,0xff,0x7e,0x3c,0x18,0,0,0))
    glyphs="""/* Generated, do not edit. WB bitmap derived from JetBrains Mono Regular v2.304.
 * Copyright 2020 The JetBrains Mono Project Authors (https://github.com/JetBrains/JetBrainsMono).
 * Licensed under SIL Open Font License 1.1. Full license: wb_jetbrains_license.h.
 * The final row is Workbench's own heart marker, not a JetBrains glyph.
 */
#ifndef WB_FONT_JETBRAINS_H
#define WB_FONT_JETBRAINS_H
#include <stdint.h>
#include <stddef.h>
enum { WB_JB_WIDTH=8, WB_JB_HEIGHT=14, WB_JB_W=8, WB_JB_H=14 };
static const uint8_t wb_jb_atlas[96][WB_JB_HEIGHT]={
"""+''.join('    {'+','.join(f'0x{r:02x}' for r in row)+'}, /* '+f'0x{i+32:02x}'+' */\n' for i,row in enumerate(rows))+"""};
static inline const uint8_t *wb_jb_glyph(unsigned char c){
    return c>=32u && c<=127u ? wb_jb_atlas[c-32u] : NULL;
}
static inline unsigned wb_jb_row(unsigned char c,unsigned row){
    const uint8_t *g=wb_jb_glyph(c);
    return g && row<WB_JB_HEIGHT ? g[row] : 0u;
}
#endif
"""
    return {"wb_font_jetbrains.h":glyphs.encode('ascii'),"wb_jetbrains_license.h":notice.encode('ascii')}

def main():
    p=argparse.ArgumentParser(description=__doc__);g=p.add_mutually_exclusive_group(required=True)
    g.add_argument("--write",action="store_true");g.add_argument("--check",action="store_true");args=p.parse_args()
    for name,data in generated().items():
        path=OUT/name
        if args.write:path.write_bytes(data)
        if path.read_bytes()!=data:raise SystemExit("NOT reproducible: "+str(path))
        print(f"{name}: {len(data)} bytes, sha256={hashlib.sha256(data).hexdigest()}")
if __name__=="__main__":main()
