/* Original 5x7 terminal punctuation and U+2665, complementing screen.inc. */
static const char mirror_extra_dict[]="!\"#$%&'()*+,;<=?@[\\]^_`{|}~\177";
static const uint8_t mirror_extra_font[][7]={
    {4,4,4,4,4,0,4},
    {10,10,10,0,0,0,0},
    {10,31,10,10,31,10,0},
    {4,15,20,14,5,30,4},
    {24,25,2,4,8,19,3},
    {12,18,20,8,21,18,13},
    {4,4,8,0,0,0,0},
    {2,4,8,8,8,4,2},
    {8,4,2,2,2,4,8},
    {0,17,10,31,10,17,0},
    {0,4,4,31,4,4,0},
    {0,0,0,0,0,4,8},
    {0,4,4,0,0,4,8},
    {1,2,4,8,4,2,1},
    {0,0,31,0,31,0,0},
    {14,17,1,2,4,0,4},
    {14,17,23,21,23,16,14},
    {14,8,8,8,8,8,14},
    {16,16,8,4,2,1,1},
    {14,2,2,2,2,2,14},
    {4,10,17,0,0,0,0},
    {0,0,0,0,0,0,31},
    {8,4,2,0,0,0,0},
    {2,4,4,8,4,4,2},
    {4,4,4,4,4,4,4},
    {8,4,4,2,4,4,8},
    {0,0,8,21,2,0,0},
    {0,10,31,31,14,4,0}
};
_Static_assert(sizeof mirror_extra_dict-1==sizeof mirror_extra_font/sizeof *mirror_extra_font,"mirror glyphs");
static const uint8_t *mirror_glyph(char c){
    const char *p=strchr(dict,c);
    if(p && *p)return font[p-dict];
    p=strchr(mirror_extra_dict,c);
    return p && *p?mirror_extra_font[p-mirror_extra_dict]:NULL;
}
