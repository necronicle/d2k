static size_t dns_encode_question(const char *name,uint16_t type,uint16_t id,uint8_t *out,size_t cap) {
    if (!name || !*name || !out || cap<17 || strlen(name)>253) return 0;
    memset(out,0,12); out[2]=1; out[5]=1;
    out[0]=(uint8_t)(id>>8);out[1]=(uint8_t)id;
    size_t at=12;
    for (const char *p=name;*p;) {
        const char *end=strchr(p,'.'); if(!end)end=p+strlen(p);
        size_t n=(size_t)(end-p);
        if(!n||n>63||at+n+6>cap)return 0;
        out[at++]=(uint8_t)n;
        for(size_t i=0;i<n;i++) {
            unsigned char c=(unsigned char)p[i];
            if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='-'||c=='_'))return 0;
            out[at++]=c;
        }
        p=*end?end+1:end;
    }
    out[at++]=0;out[at++]=(uint8_t)(type>>8);out[at++]=(uint8_t)type;out[at++]=0;out[at++]=1;
    return at;
}
