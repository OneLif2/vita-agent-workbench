/* Native same-family libssh + mbedTLS interop probe. Never reads / writes key files. */
#include <libssh/libssh.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    ssh_key a=NULL,b=NULL; char *text=NULL; unsigned char *ha=NULL,*hb=NULL;
    size_t na=0,nb=0; int rc=1;
    if(ssh_init()!=SSH_OK) return 2;
    if(ssh_pki_generate_key(SSH_KEYTYPE_ECDSA_P256,0,&a)!=SSH_OK){rc=3;goto done;}
    if(ssh_pki_export_privkey_base64_format(a,NULL,NULL,NULL,&text,SSH_FILE_FORMAT_OPENSSH)!=SSH_OK || !text){rc=4;goto done;}
    if(strlen(text)>4096 || ssh_pki_import_privkey_base64(text,NULL,NULL,NULL,&b)!=SSH_OK){rc=5;goto done;}
    if(!ssh_key_is_private(b) || ssh_key_type(b)!=SSH_KEYTYPE_ECDSA_P256){rc=6;goto done;}
    if(ssh_get_publickey_hash(a,SSH_PUBLICKEY_HASH_SHA256,&ha,&na)!=SSH_OK ||
       ssh_get_publickey_hash(b,SSH_PUBLICKEY_HASH_SHA256,&hb,&nb)!=SSH_OK ||
       na!=32 || na!=nb || memcmp(ha,hb,32)!=0) {rc=7;goto done;}
    puts("PASS: generated disposable P-256 -> explicit OpenSSH text in memory -> imported P-256 private -> identical 32-byte public digest");rc=0;
done:
    if(ha) ssh_clean_pubkey_hash(&ha);
    if(hb) ssh_clean_pubkey_hash(&hb);
    if(text) {volatile char *p=text;size_t n=strlen(text);while(n--)*p++=0;ssh_string_free_char(text);}
    ssh_key_free(a);ssh_key_free(b);ssh_finalize();
    if(rc) fprintf(stderr,"FAIL stage=%d\n",rc);
    return rc;
}
