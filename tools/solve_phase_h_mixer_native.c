#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define OLD_LEN 80u
#define TARGET_LEN 80u
#define MAX_USED 4096u

static uint32_t rol32(uint32_t v, unsigned n){ return (v<<n)|(v>>(32u-n)); }
static uint32_t rd_le32(const uint8_t*p){return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);} 
static uint32_t rd_be32(const uint8_t*p){return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|(uint32_t)p[3];}
static void wr_le32(uint8_t*p,uint32_t v){p[0]=(uint8_t)v;p[1]=(uint8_t)(v>>8);p[2]=(uint8_t)(v>>16);p[3]=(uint8_t)(v>>24);} 

static void sha1_compress(uint32_t s[5], const uint8_t block[64], int little){
    uint32_t w[80];
    for(unsigned i=0;i<16;i++) w[i]=little?rd_le32(block+4u*i):rd_be32(block+4u*i);
    for(unsigned i=16;i<80;i++) w[i]=rol32(w[i-3]^w[i-8]^w[i-14]^w[i-16],1);
    uint32_t a=s[0],b=s[1],c=s[2],d=s[3],e=s[4];
    for(unsigned i=0;i<80;i++){
        uint32_t f,k;
        if(i<20){f=(b&c)|((~b)&d);k=0x5A827999u;}
        else if(i<40){f=b^c^d;k=0x6ED9EBA1u;}
        else if(i<60){f=(b&c)|(b&d)|(c&d);k=0x8F1BBCDCu;}
        else{f=b^c^d;k=0xCA62C1D6u;}
        uint32_t t=rol32(a,5)+f+e+k+w[i]; e=d; d=c; c=rol32(b,30); b=a; a=t;
    }
    s[0]+=a;s[1]+=b;s[2]+=c;s[3]+=d;s[4]+=e;
}

static void ksec_hash(const uint8_t*msg,size_t len,uint8_t out[20]){
    uint32_t s[5]={0x67452301u,0xEFCDAB89u,0x98BADCFEu,0x10325476u,0xC3D2E1F0u};
    size_t complete=len/64u;
    for(size_t i=0;i<complete;i++) sha1_compress(s,msg+64u*i,1);
    size_t rem=len-complete*64u;
    size_t pad=64u-(len&0x3fu); if(pad<=8u) pad+=64u;
    size_t flen=rem+pad;
    uint8_t fin[128]; memset(fin,0,sizeof(fin)); memcpy(fin,msg+complete*64u,rem); fin[rem]=0x80u;
    uint64_t bits=(uint64_t)len*8u;
    wr_le32(fin+flen-8u,(uint32_t)(bits>>32)); wr_le32(fin+flen-4u,(uint32_t)bits);
    for(size_t off=0;off<flen;off+=64u) sha1_compress(s,fin+off,0);
    for(unsigned i=0;i<5;i++) wr_le32(out+4u*i,s[i]);
}

static void replay_mixer(const uint8_t*ws,size_t used,const uint8_t old[OLD_LEN],uint8_t out[TARGET_LEN]){
    size_t q=used/4u, mlen=40u+2u*q;
    uint8_t *m=(uint8_t*)malloc(mlen); if(!m){fprintf(stderr,"malloc failed\n");exit(2);} 
    const uint8_t *q0=ws,*q1=ws+q,*q2=ws+2u*q,*q3=ws+3u*q;
    const uint8_t *s0=old,*s1=old+20u,*s2=old+40u,*s3=old+60u;
    uint8_t a[20],b[20],c[20],d[20],pair[40]; size_t p;
#define H4(OUT,SA,QA,SB,QB) do{p=0;memcpy(m+p,(SA),20);p+=20;memcpy(m+p,(QA),q);p+=q;memcpy(m+p,(SB),20);p+=20;memcpy(m+p,(QB),q);p+=q;ksec_hash(m,p,(OUT));}while(0)
    H4(a,s0,q0,s1,q1); H4(b,s1,q1,s0,q0); H4(c,s2,q2,s3,q3); H4(d,s3,q3,s2,q2);
#undef H4
    memcpy(pair,a,20);memcpy(pair+20,c,20);ksec_hash(pair,40,out);
    memcpy(pair,b,20);memcpy(pair+20,d,20);ksec_hash(pair,40,out+20);
    memcpy(pair,c,20);memcpy(pair+20,a,20);ksec_hash(pair,40,out+40);
    memcpy(pair,d,20);memcpy(pair+20,b,20);ksec_hash(pair,40,out+60);
    free(m);
}

static int nib(char c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1;}
static int dechex(const char*s,uint8_t*out,size_t n){if(strlen(s)!=2u*n)return 0;for(size_t i=0;i<n;i++){int h=nib(s[2*i]),l=nib(s[2*i+1]);if(h<0||l<0)return 0;out[i]=(uint8_t)((h<<4)|l);}return 1;}
static void prhex(const uint8_t*p,size_t n){static const char h[]="0123456789abcdef";for(size_t i=0;i<n;i++){putchar(h[p[i]>>4]);putchar(h[p[i]&15]);}}
static uint64_t u64(const char*s,const char*n){errno=0;char*e=NULL;uint64_t v=strtoull(s,&e,0);if(errno||!e||*e){fprintf(stderr,"invalid %s\n",n);exit(2);}return v;}

static void hidden(const char*profile,unsigned k,unsigned*ob,unsigned*wb){
    if(!strcmp(profile,"OLD")){*ob=k;*wb=0;} else if(!strcmp(profile,"WS")){*ob=0;*wb=k;} else if(!strcmp(profile,"SPLIT")){*ob=(k+1u)/2u;*wb=k/2u;} else{fprintf(stderr,"bad profile\n");exit(2);} }
static void setlow(uint8_t*d,size_t n,uint64_t v,unsigned bits){for(unsigned b=0;b<bits;b++){size_t i=n-1u-b/8u;uint8_t m=(uint8_t)(1u<<(b&7u));if(v&(UINT64_C(1)<<b))d[i]|=m;else d[i]&=(uint8_t)~m;}}
static double nowsec(void){struct timespec ts;if(clock_gettime(CLOCK_MONOTONIC,&ts)){perror("clock_gettime");exit(2);}return (double)ts.tv_sec+(double)ts.tv_nsec/1e9;}

int main(int argc,char**argv){
    if(argc!=10){fprintf(stderr,"usage: %s PROFILE K USED OLD_KNOWN_HEX WS_KNOWN_HEX TARGET_HEX START COUNT MODE\n",argv[0]);return 2;}
    const char*profile=argv[1]; unsigned k=(unsigned)u64(argv[2],"K"); size_t used=(size_t)u64(argv[3],"USED");
    uint64_t start=u64(argv[7],"START"), req=u64(argv[8],"COUNT"); const char*mode=argv[9];
    if(k<1||k>32||used!=600||used>MAX_USED||used%4){fprintf(stderr,"unsupported K/USED\n");return 2;}
    if(strcmp(mode,"search")&&strcmp(mode,"bench")){fprintf(stderr,"MODE must be search or bench\n");return 2;}
    unsigned oldbits,wsbits; hidden(profile,k,&oldbits,&wsbits);
    uint8_t oldbase[OLD_LEN],wsbase[MAX_USED],target[TARGET_LEN];
    if(!dechex(argv[4],oldbase,OLD_LEN)||!dechex(argv[5],wsbase,used)||!dechex(argv[6],target,TARGET_LEN)){fprintf(stderr,"invalid hex input\n");return 2;}
    uint64_t space=UINT64_C(1)<<k; if(start>=space){fprintf(stderr,"START outside space\n");return 2;} uint64_t rem=space-start; uint64_t count=(req==0||req>rem)?rem:req;
    uint8_t old[OLD_LEN],ws[MAX_USED],mix[TARGET_LEN],bestold[OLD_LEN],bestws[MAX_USED];
    uint64_t tested=0,matches=0,first=0; int have=0; double t0=nowsec();
    for(uint64_t off=0;off<count;off++){
        uint64_t ctr=start+off; memcpy(old,oldbase,OLD_LEN); memcpy(ws,wsbase,used);
        uint64_t ov=oldbits?(ctr&((UINT64_C(1)<<oldbits)-1u)):0; uint64_t wv=wsbits?(ctr>>oldbits):0;
        setlow(old,OLD_LEN,ov,oldbits); setlow(ws,used,wv,wsbits); replay_mixer(ws,used,old,mix); tested++;
        if(!memcmp(mix,target,TARGET_LEN)){matches++;if(!have){have=1;first=ctr;memcpy(bestold,old,OLD_LEN);memcpy(bestws,ws,used);}if(!strcmp(mode,"search"))break;}
    }
    double elapsed=nowsec()-t0,rate=elapsed>0?(double)tested/elapsed:0.0;
    printf("PROFILE=%s\nK=%u\nUSED=%zu\nMODE=%s\nSTART=%" PRIu64 "\nRANGE_COUNT=%" PRIu64 "\nTESTED=%" PRIu64 "\nMATCHES=%" PRIu64 "\n",profile,k,used,mode,start,count,tested,matches);
    printf("STATUS=%s\n",!strcmp(mode,"search")?(have?"FOUND":"NOT_FOUND"):"BENCHMARK_COMPLETE");
    if(have){printf("FIRST_MATCH_COUNTER=%" PRIu64 "\nCANDIDATE_OLD_STATE_HEX=",first);prhex(bestold,OLD_LEN);printf("\nCANDIDATE_WORKSPACE_PREFIX_HEX=");prhex(bestws,used);putchar('\n');}
    printf("ELAPSED_SECONDS=%.9f\nTHROUGHPUT_CANDIDATES_PER_SECOND=%.3f\n",elapsed,rate);
    return 0;
}
