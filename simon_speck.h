#ifndef SIMON_SPECK_H
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define u8 uint8_t
#define u32 uint32_t
#define u64 uint64_t

#define ROTL32(x,r) (((x)<<(r)) | (x>>(32-(r))))
#define ROTR32(x,r) (((x)>>(r)) | ((x)<<(32-(r))))
#define ROTL64(x,r) (((x)<<(r)) | (x>>(64-(r))))
#define ROTR64(x,r) (((x)>>(r)) | ((x)<<(64-(r))))

#define ER32(x,y,k) (x=ROTR32(x,8), x+=y, x^=k, y=ROTL32(y,3), y^=x)
#define DR32(x,y,k) (y^=x, y=ROTR32(y,3), x^=k, x-=y, x=ROTL32(x,8))

#define f32(x) ((ROTL32(x,1) & ROTL32(x,8)) ^ ROTL32(x,2))
#define R32x2(x,y,k1,k2) (y^=f32(x), y^=k1, x^=f32(y), x^=k2)

void Words32ToBytes(u32 words[],u8 bytes[],int numwords){
    int i,j=0;
    for(i=0;i<numwords;i++){
    bytes[j]=(u8)words[i];
    bytes[j+1]=(u8)(words[i]>>8);
    bytes[j+2]=(u8)(words[i]>>16);
    bytes[j+3]=(u8)(words[i]>>24);
    j+=4;
    }
}

void BytesToWords32(u8 bytes[],u32 words[],int numbytes){
    int j=0;
    for(int i=0;i<numbytes/4;i++){
    words[i]=(u32)bytes[j] | ((u32)bytes[j+1]<<8) | ((u32)bytes[j+2]<<16) |
    ((u32)bytes[j+3]<<24);
        j+=4;
   // printf("Word[%d]: 0x%08X\n", i, words[i]);
    } 
}

/*****************Speck64128*****************/

void Speck64128KeySchedule(u32 K[],u32 rk[])
{
    u32 i,D=K[3],C=K[2],B=K[1],A=K[0];
    for(i=0;i<27;){
    rk[i]=A; ER32(B,A,i++);
    rk[i]=A; ER32(C,A,i++);
    rk[i]=A; ER32(D,A,i++);
    }
}

void Speck64128Encrypt(u32 Pt[],u32 Ct[],u32 rk[]){
    u32 i;
    Ct[0]=Pt[0]; Ct[1]=Pt[1];
    for(i=0;i<27;) {
        ER32(Ct[1],Ct[0],rk[i++]);
    }
}

void Speck64128Decrypt(u32 Pt[],u32 Ct[],u32 rk[]){
    int i;
    Pt[0]=Ct[0]; Pt[1]=Ct[1];
    for(i=26;i>=0;) DR32(Pt[1],Pt[0],rk[i--]);
}

/*****************Simon64128*****************/
void Simon64128KeySchedule(u32 K[],u32 rk[]){
    u32 i,c=0xfffffffc;
    u64 z=0xfc2ce51207a635dbLL;
    rk[0]=K[0]; rk[1]=K[1]; rk[2]=K[2]; rk[3]=K[3];
    for(i=4;i<44;i++){
        rk[i]=c^(z&1)^rk[i-4]^ROTR32(rk[i-1],3)^rk[i-3]
        ^ROTR32(rk[i-1],4)^ROTR32(rk[i-3],1);
        z>>=1;
    }
    for (int i = 0; i < 44; i++) {
       // printf("rk[%d]: 0x%08X\n", i, rk[i]);
    }
}

void Simon64128Encrypt(u32 Pt[],u32 Ct[],u32 rk[]){
    u32 i;
    Ct[1]=Pt[1]; Ct[0]=Pt[0];
    for(i=0;i<44;) R32x2(Ct[1],Ct[0],rk[i++],rk[i++]);
   // printf("Pt[%d]: (%08x , %08x)\n", i,Ct[1], Ct[0]);
	
}

void Simon64128Decrypt(u32 Pt[],u32 Ct[],u32 rk[]){
    int i;
    Pt[1]=Ct[1]; Pt[0]=Ct[0];
    for(i=43;i>=0;) R32x2(Pt[0],Pt[1],rk[i--],rk[i--]);
}

void stringToByteArray(u8 *str, u8 *byteArray) {
    int length = strlen((const char*)str);
    for (int i = 0; i < length; i++) {
        byteArray[i] = (u8)str[i];
    }
}

/****************Simon6496*********************/

void Simon6496KeySchedule(u32 K[],u32 rk[]){
    u32 i,c=0xfffffffc;
    u64 z=0x7369f885192c0ef5LL;
    rk[0]=K[0]; rk[1]=K[1]; rk[2]=K[2];
    for(i=3;i<42;i++){
        rk[i]=c^(z&1)^rk[i-3]^ROTR32(rk[i-1],3)^ROTR32(rk[i-1],4);
        z>>=1;
    }
    // for (int i = 0; i < 42; i++) {
    //     printf("rk[%d]: 0x%08X\n", i, rk[i]);
    // }
}

void Simon6496Encrypt(u32 Pt[],u32 Ct[],u32 rk[]){
    u32 i;
    Ct[1]=Pt[1]; Ct[0]=Pt[0];
    for(i=0;i<42;) R32x2(Ct[1],Ct[0],rk[i++],rk[i++]);
    //  printf("Pt[%d]: (%08x , %08x)\n", i,Ct[1], Ct[0]);
    
}

void Simon6496Decrypt(u32 Pt[],u32 Ct[],u32 rk[]){
    int i;
    Pt[1]=Ct[1]; Pt[0]=Ct[0];
    for(i=41;i>=0;) R32x2(Pt[0],Pt[1],rk[i--],rk[i--]);
}


/****************Speck6496*********************/
void Speck6496KeySchedule(u32 K[],u32 rk[]){
    u32 i,C=K[2],B=K[1],A=K[0];
    for(i=0;i<26;){
        rk[i]=A; ER32(B,A,i++);
        rk[i]=A; ER32(C,A,i++);
    }
}
void Speck6496Encrypt(u32 Pt[],u32 Ct[],u32 rk[]){
    u32 i;
    Ct[0]=Pt[0]; Ct[1]=Pt[1];
    for(i=0;i<26;) ER32(Ct[1],Ct[0],rk[i++]);
}

void Speck6496Decrypt(u32 Pt[],u32 Ct[],u32 rk[]){
    int i;
    Pt[0]=Ct[0]; Pt[1]=Ct[1];
    for(i=25;i>=0;) DR32(Pt[1],Pt[0],rk[i--]);
}



#endif
