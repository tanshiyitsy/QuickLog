#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

// #include <stdio>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/ktime.h>
#include <linux/sort.h>
#include <linux/moduleparam.h>

//#include <asm/i387.h>//linux version <5
#include <asm/fpu/api.h> //version =5



#define  _MM_MALLOC_H_INCLUDED
#include <x86intrin.h>
#undef _MM_MALLOC_H_INCLUDED

#include <linux/siphash.h>

#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/audit.h>
#include <linux/lsm_audit.h>


static int len= 1024; //generating size, 这个值要在脚本里改，这里改没有用
module_param(len,int,S_IRUGO);  

// #define iteration 200000
#define iteration 1000

typedef __m128i block;
typedef struct {block rd_key[11]; } AES_KEY;

// aeskey是生成固定密钥时提供的user_key
// const_aeskey是生成的固定密钥，一旦生成，后续不变
const static unsigned char aeskey[16] = {'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p'};
static AES_KEY const_aeskey;
static block current_key, current_state, q2_tag;
static unsigned long long my_time[1048576];


/**
 * 我定义的变量
 * light_current_key = user_key
*/
static block light_current_key, light_current_state;
unsigned long long appd_tag_to_log_time = 0;  // 把生成的tag，附加到字符串的时间，这个时间固定

/* Some helper functions */
#define rnds 10 //AES rounds
#define xor_block(x,y)        _mm_xor_si128(x,y)
#define zero_block()          _mm_setzero_si128()
/*Load 14-byte log data after the 2-byte counter*/
#define gen_logging_blk(log,ctr) _mm_insert_epi16(_mm_loadu_si128(log), ctr, 0)

// Sources:
// Dead Store Elimination (Still) Considered Harmful, USENIX 2017
// https://compsec.sysnet.ucsd.edu/secure_memzero.h
//
/**
 * __m128i _mm_aeskeygenassist_si128(__m128i ckey, const int rcon);   https://blog.csdn.net/fengbingchun/article/details/22323607
 * 根据输入的m128i生成一个 m128i的轮密钥，第二个参数必须是一个编译时常数
 * AES加密要求10轮迭代，每一轮需要一个不同的128位的轮密钥，这个指令帮忙生成所有的轮密钥
 * 
 * _mm_shuffle_ps(a: __m128, b: __m128, const MASK: i32) -> __m128
 * 使用MASK对a和b中的压缩单精度（32位）浮点元素进行解算。结果的下半部分取a的值，上半部分取b的值。掩码被拆分为2个控制位，每个控制位用于从输入中索引元素。
 * 
 * _mm_castps_si128(a: __m128) -> __m128i
 * 将〔4 x float〕的128位浮点向量转换为128位整数向量。
*/

#define EXPAND_ASSIST(v1,v2,v3,v4,shuff_const,aes_const)                    \
  do{                                                                       \
    v2 = _mm_aeskeygenassist_si128(v4,aes_const);                           \
    v3 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(v3),              \
                                         _mm_castsi128_ps(v1), 16));        \
    v1 = _mm_xor_si128(v1,v3);                                              \
    v3 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(v3),              \
                                         _mm_castsi128_ps(v1), 140));       \
    v1 = _mm_xor_si128(v1,v3);                                              \
    v2 = _mm_shuffle_epi32(v2,shuff_const);                                 \
    v1 = _mm_xor_si128(v1,v2);                                              \
  } while(0)


void AES_128_Key_Expansion(const unsigned char *userkey, void *key)
{
    __m128i x0,x1,x2;
    __m128i *kp = (__m128i *)key;
    kp[0] = x0 = _mm_loadu_si128((__m128i*)userkey);
    x2 = _mm_setzero_si128();
    EXPAND_ASSIST(x0,x1,x2,x0,255,1);   kp[1]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,2);   kp[2]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,4);   kp[3]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,8);   kp[4]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,16);  kp[5]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,32);  kp[6]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,64);  kp[7]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,128); kp[8]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,27);  kp[9]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,54);  kp[10] = x0;
}
#undef EXPAND_ASSIST

//----------------------------------------------------

//AES pre-round 8 blocks

#define gen_7_blks(cipher_blks,log_msg,counter)                            \
    do{                                                                    \
		cipher_blks[1]  = gen_logging_blk((block*)(log_msg+12),(counter+2)); \
		cipher_blks[2]  = gen_logging_blk((block*)(log_msg+26),(counter+3)); \
		cipher_blks[3]  = gen_logging_blk((block*)(log_msg+40),(counter+4)); \
		cipher_blks[4]  = gen_logging_blk((block*)(log_msg+54),(counter+5)); \
		cipher_blks[5]  = gen_logging_blk((block*)(log_msg+68),(counter+6)); \
		cipher_blks[6]  = gen_logging_blk((block*)(log_msg+82),(counter+7)); \
		cipher_blks[7]  = gen_logging_blk((block*)(log_msg+96),(counter+8)); \
	} while(0)


//AES pre-round 8 blocks
#define prernd_8(cipher_blks, key)                       \
	do{                                                  \
		cipher_blks[0] = xor_block(cipher_blks[0], key); \
		cipher_blks[1] = xor_block(cipher_blks[1], key); \
		cipher_blks[2] = xor_block(cipher_blks[2], key); \
		cipher_blks[3] = xor_block(cipher_blks[3], key); \
		cipher_blks[4] = xor_block(cipher_blks[4], key); \
		cipher_blks[5] = xor_block(cipher_blks[5], key); \
		cipher_blks[6] = xor_block(cipher_blks[6], key); \
		cipher_blks[7] = xor_block(cipher_blks[7], key); \
	} while(0)
	
//AES Pre-round 4 blocks
#define prernd_4(cipher_blks,sign_keys) 			       \
  do{                                                      \
    cipher_blks[0] = xor_block(cipher_blks[0], sign_keys); \
    cipher_blks[1] = xor_block(cipher_blks[1], sign_keys); \
    cipher_blks[2] = xor_block(cipher_blks[2], sign_keys); \
    cipher_blks[3] = xor_block(cipher_blks[3], sign_keys); \
  } while(0)


//XOR 8 cipher blocks

#define tag_8_xor(tag_blks,cipher_blks)  \
  do{  \
	tag_blks[0] =xor_block(xor_block(cipher_blks[0], cipher_blks[1]), xor_block(cipher_blks[2], cipher_blks[3]));  \
	tag_blks[1] =xor_block(xor_block(cipher_blks[4], cipher_blks[5]), xor_block(cipher_blks[6], cipher_blks[7]));  \
	tag_blks[2] =xor_block(tag_blks[2], xor_block(tag_blks[0], tag_blks[1]));                                      \
  } while(0)


#define enc_8(cipher_blks, key)                                 \
	do{                                                         \
		cipher_blks[1] = _mm_aesenc_si128(cipher_blks[1], key); \
		cipher_blks[0] = _mm_aesenc_si128(cipher_blks[0], key); \
		cipher_blks[2] = _mm_aesenc_si128(cipher_blks[2], key); \
		cipher_blks[3] = _mm_aesenc_si128(cipher_blks[3], key); \
		cipher_blks[4] = _mm_aesenc_si128(cipher_blks[4], key); \
		cipher_blks[5] = _mm_aesenc_si128(cipher_blks[5], key); \
		cipher_blks[6] = _mm_aesenc_si128(cipher_blks[6], key); \
		cipher_blks[7] = _mm_aesenc_si128(cipher_blks[7], key); \
  	}while(0)



#define enc_4(cipher_blks, key)                                 \
	do{                                                         \
		cipher_blks[0] = _mm_aesenc_si128(cipher_blks[0], key); \
		cipher_blks[1] = _mm_aesenc_si128(cipher_blks[1], key); \
		cipher_blks[2] = _mm_aesenc_si128(cipher_blks[2], key); \
		cipher_blks[3] = _mm_aesenc_si128(cipher_blks[3], key); \
  	}while(0)


#define enc_3(cipher_blks, key)                                 \
	do{                                                         \
		cipher_blks[0] = _mm_aesenc_si128(cipher_blks[0], key); \
		cipher_blks[1] = _mm_aesenc_si128(cipher_blks[1], key); \
		cipher_blks[2] = _mm_aesenc_si128(cipher_blks[2], key); \
  	}while(0)


#define enc_2(cipher_blks, key)                                 \
	do{                                                         \
		cipher_blks[0] = _mm_aesenc_si128(cipher_blks[0], key); \
		cipher_blks[1] = _mm_aesenc_si128(cipher_blks[1], key); \
  	}while(0)


/*Marcos used to unrolling ECB*/

#define aes_single(cipher_blks, sched)                               \
	do{                                                              \
		cipher_blks[0] = _mm_aesenc_si128(cipher_blks[0], sched[1]); \
		cipher_blks[0] = _mm_aesenc_si128(cipher_blks[0], sched[2]); \
		cipher_blks[0] = _mm_aesenc_si128(cipher_blks[0], sched[3]); \
		cipher_blks[0] = _mm_aesenc_si128(cipher_blks[0], sched[4]); \
		cipher_blks[0] = _mm_aesenc_si128(cipher_blks[0], sched[5]); \
		cipher_blks[0] = _mm_aesenc_si128(cipher_blks[0], sched[6]); \
		cipher_blks[0] = _mm_aesenc_si128(cipher_blks[0], sched[7]); \
		cipher_blks[0] = _mm_aesenc_si128(cipher_blks[0], sched[8]); \
		cipher_blks[0] = _mm_aesenc_si128(cipher_blks[0], sched[9]); \
		cipher_blks[0] =_mm_aesenclast_si128(cipher_blks[0], sched[10]);\
	} while(0)


#define AES_ECB_2(cipher_blks, sched)   \
	do{     \
		enc_2(cipher_blks, sched[1]);              \
		enc_2(cipher_blks, sched[2]);              \
		enc_2(cipher_blks, sched[3]);              \
		enc_2(cipher_blks, sched[4]);              \
		enc_2(cipher_blks, sched[5]);              \
		enc_2(cipher_blks, sched[6]);              \
		enc_2(cipher_blks, sched[7]);              \
		enc_2(cipher_blks, sched[8]);              \
		enc_2(cipher_blks, sched[9]);              \
		cipher_blks[0] =_mm_aesenclast_si128(cipher_blks[0], sched[10]); \
		cipher_blks[1] =_mm_aesenclast_si128(cipher_blks[1], sched[10]); \
	}while (0)


#define AES_ECB_3(cipher_blks, sched)    \
	do{                                  \
		enc_3(cipher_blks, sched[1]);              \
		enc_3(cipher_blks, sched[2]);              \
		enc_3(cipher_blks, sched[3]);              \
		enc_3(cipher_blks, sched[4]);              \
		enc_3(cipher_blks, sched[5]);              \
		enc_3(cipher_blks, sched[6]);              \
		enc_3(cipher_blks, sched[7]);              \
		enc_3(cipher_blks, sched[8]);              \
		enc_3(cipher_blks, sched[9]);              \
		cipher_blks[0] =_mm_aesenclast_si128(cipher_blks[0], sched[10]); \
		cipher_blks[1] =_mm_aesenclast_si128(cipher_blks[1], sched[10]); \
		cipher_blks[3] =_mm_aesenclast_si128(cipher_blks[1], sched[10]); \
	}while (0)



#define AES_ECB_4(cipher_blks, sched, sign_keys)   \
	do{                                        	   \
		prernd_4(cipher_blks,sign_keys);           \
		enc_4(cipher_blks, sched[1]);              \
		enc_4(cipher_blks, sched[2]);              \
		enc_4(cipher_blks, sched[3]);              \
		enc_4(cipher_blks, sched[4]);              \
		enc_4(cipher_blks, sched[5]);              \
		enc_4(cipher_blks, sched[6]);              \
		enc_4(cipher_blks, sched[7]);              \
		enc_4(cipher_blks, sched[8]);              \
		enc_4(cipher_blks, sched[9]);              \
		cipher_blks[0] =_mm_aesenclast_si128(cipher_blks[0], sched[10]); \
		cipher_blks[1] =_mm_aesenclast_si128(cipher_blks[1], sched[10]); \
		cipher_blks[2] =_mm_aesenclast_si128(cipher_blks[2], sched[10]); \
		cipher_blks[3] =_mm_aesenclast_si128(cipher_blks[3], sched[10]); \
	}while (0)


// prernd_8 是在干嘛, 是在对8个块的原始内容，异或上sign_keys
// _mm_aesenclast_si128 是AES的最后一轮加密，sched[10]是round_key
// enc里使用的_mm_aesenc_si128(cipher_blks[6], key)是AES中的标准轮
#define AES_ECB_8(cipher_blks, sched, sign_keys)   \
	do{                                        	   \
		prernd_8(cipher_blks,sign_keys);           \
		enc_8(cipher_blks, sched[1]);              \
		enc_8(cipher_blks, sched[2]);              \
		enc_8(cipher_blks, sched[3]);              \
		enc_8(cipher_blks, sched[4]);              \
		enc_8(cipher_blks, sched[5]);              \
		enc_8(cipher_blks, sched[6]);              \
		enc_8(cipher_blks, sched[7]);              \
		enc_8(cipher_blks, sched[8]);              \
		enc_8(cipher_blks, sched[9]);              \
		cipher_blks[0] =_mm_aesenclast_si128(cipher_blks[0], sched[10]); \
		cipher_blks[1] =_mm_aesenclast_si128(cipher_blks[1], sched[10]); \
		cipher_blks[2] =_mm_aesenclast_si128(cipher_blks[2], sched[10]); \
		cipher_blks[3] =_mm_aesenclast_si128(cipher_blks[3], sched[10]); \
		cipher_blks[4] =_mm_aesenclast_si128(cipher_blks[4], sched[10]); \
		cipher_blks[5] =_mm_aesenclast_si128(cipher_blks[5], sched[10]); \
		cipher_blks[6] =_mm_aesenclast_si128(cipher_blks[6], sched[10]); \
		cipher_blks[7] =_mm_aesenclast_si128(cipher_blks[7], sched[10]); \
	}while (0)

/**
 * 我的宏定义
*/
#define light_gen_8_blks(cipher_blks,log_msg,counter)                            \
    do{                                                                    \
		cipher_blks[0]  = gen_logging_blk((block*)(log_msg),(counter+1)); \
		cipher_blks[1]  = gen_logging_blk((block*)(log_msg+14),(counter+2)); \
		cipher_blks[2]  = gen_logging_blk((block*)(log_msg+28),(counter+3)); \
		cipher_blks[3]  = gen_logging_blk((block*)(log_msg+42),(counter+4)); \
		cipher_blks[4]  = gen_logging_blk((block*)(log_msg+56),(counter+5)); \
		cipher_blks[5]  = gen_logging_blk((block*)(log_msg+70),(counter+6)); \
		cipher_blks[6]  = gen_logging_blk((block*)(log_msg+84),(counter+7)); \
		cipher_blks[7]  = gen_logging_blk((block*)(log_msg+98),(counter+8)); \
	} while(0)

// _mm_aesenclast_si128 是AES的最后一轮加密
// enc里使用的_mm_aesenc_si128(cipher_blks[6], key)是AES中的标准轮
#define LIGHT_AES_ECB_8(cipher_blks, round_keys)   \
	do{                                        	   \
		enc_8(cipher_blks, round_keys[1]);              \
		enc_8(cipher_blks, round_keys[2]);              \
		enc_8(cipher_blks, round_keys[3]);              \
		enc_8(cipher_blks, round_keys[4]);              \
		enc_8(cipher_blks, round_keys[5]);              \
		enc_8(cipher_blks, round_keys[6]);              \
		enc_8(cipher_blks, round_keys[7]);              \
		enc_8(cipher_blks, round_keys[8]);              \
		enc_8(cipher_blks, round_keys[9]);              \
		cipher_blks[0] =_mm_aesenclast_si128(cipher_blks[0], round_keys[10]); \
		cipher_blks[1] =_mm_aesenclast_si128(cipher_blks[1], round_keys[10]); \
		cipher_blks[2] =_mm_aesenclast_si128(cipher_blks[2], round_keys[10]); \
		cipher_blks[3] =_mm_aesenclast_si128(cipher_blks[3], round_keys[10]); \
		cipher_blks[4] =_mm_aesenclast_si128(cipher_blks[4], round_keys[10]); \
		cipher_blks[5] =_mm_aesenclast_si128(cipher_blks[5], round_keys[10]); \
		cipher_blks[6] =_mm_aesenclast_si128(cipher_blks[6], round_keys[10]); \
		cipher_blks[7] =_mm_aesenclast_si128(cipher_blks[7], round_keys[10]); \
	}while (0)

#define LIGHT_AES_ECB_4(cipher_blks, sched)   \
	do{                                        	   \
		enc_4(cipher_blks, sched[1]);              \
		enc_4(cipher_blks, sched[2]);              \
		enc_4(cipher_blks, sched[3]);              \
		enc_4(cipher_blks, sched[4]);              \
		enc_4(cipher_blks, sched[5]);              \
		enc_4(cipher_blks, sched[6]);              \
		enc_4(cipher_blks, sched[7]);              \
		enc_4(cipher_blks, sched[8]);              \
		enc_4(cipher_blks, sched[9]);              \
		cipher_blks[0] =_mm_aesenclast_si128(cipher_blks[0], sched[10]); \
		cipher_blks[1] =_mm_aesenclast_si128(cipher_blks[1], sched[10]); \
		cipher_blks[2] =_mm_aesenclast_si128(cipher_blks[2], sched[10]); \
		cipher_blks[3] =_mm_aesenclast_si128(cipher_blks[3], sched[10]); \
	}while (0)


#define LIGHT_AES_ECB_2(cipher_blks, sched)   \
	do{     \
		enc_2(cipher_blks, sched[1]);              \
		enc_2(cipher_blks, sched[2]);              \
		enc_2(cipher_blks, sched[3]);              \
		enc_2(cipher_blks, sched[4]);              \
		enc_2(cipher_blks, sched[5]);              \
		enc_2(cipher_blks, sched[6]);              \
		enc_2(cipher_blks, sched[7]);              \
		enc_2(cipher_blks, sched[8]);              \
		enc_2(cipher_blks, sched[9]);              \
		cipher_blks[0] =_mm_aesenclast_si128(cipher_blks[0], sched[10]); \
		cipher_blks[1] =_mm_aesenclast_si128(cipher_blks[1], sched[10]); \
	}while (0)




#define AES_128_key_exp(k, rcon) aes_128_key_expansion(k, _mm_aeskeygenassist_si128(k, rcon))

static __m128i aes_128_key_expansion(__m128i key, __m128i keygened){
    keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3,3,3,3));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, keygened);
}

//public API uint8_t *enc_key --> 
static void aes128_load_key_enc_only(const __m128i* enc_key, __m128i *key_schedule){
    // key_schedule[0] = _mm_loadu_si128((const __m128i*) enc_key);
	key_schedule[0] = _mm_loadu_si128(enc_key);
    key_schedule[1]  = AES_128_key_exp(key_schedule[0], 0x01);
    key_schedule[2]  = AES_128_key_exp(key_schedule[1], 0x02);
    key_schedule[3]  = AES_128_key_exp(key_schedule[2], 0x04);
    key_schedule[4]  = AES_128_key_exp(key_schedule[3], 0x08);
    key_schedule[5]  = AES_128_key_exp(key_schedule[4], 0x10);
    key_schedule[6]  = AES_128_key_exp(key_schedule[5], 0x20);
    key_schedule[7]  = AES_128_key_exp(key_schedule[6], 0x40);
    key_schedule[8]  = AES_128_key_exp(key_schedule[7], 0x80);
    key_schedule[9]  = AES_128_key_exp(key_schedule[8], 0x1B);
    key_schedule[10] = AES_128_key_exp(key_schedule[9], 0x36);
}

#define light_aes_single(cipher_blk, sched)                               \
	do{                                                              \
		cipher_blk = _mm_aesenc_si128(cipher_blk, sched[1]); \
		cipher_blk = _mm_aesenc_si128(cipher_blk, sched[2]); \
		cipher_blk = _mm_aesenc_si128(cipher_blk, sched[3]); \
		cipher_blk = _mm_aesenc_si128(cipher_blk, sched[4]); \
		cipher_blk = _mm_aesenc_si128(cipher_blk, sched[5]); \
		cipher_blk = _mm_aesenc_si128(cipher_blk, sched[6]); \
		cipher_blk = _mm_aesenc_si128(cipher_blk, sched[7]); \
		cipher_blk = _mm_aesenc_si128(cipher_blk, sched[8]); \
		cipher_blk = _mm_aesenc_si128(cipher_blk, sched[9]); \
		cipher_blk =_mm_aesenclast_si128(cipher_blk, sched[10]);\
	} while(0)

//end of marcos---------------------------------------------

static void cmpt_4_blks(block *cipher_blks, uint16_t counter, const char *log_msg, const block *sched, block sign_keys)
{
	if(counter){		
		cipher_blks[0]  = gen_logging_blk((block*)(log_msg),counter+1); 
	}else{//contains the first block
		cipher_blks[0]  = _mm_srli_si128(_mm_loadu_si128((block*)log_msg), 2);
		cipher_blks[0]  = _mm_insert_epi16(cipher_blks[0], counter+1, 0);
	}
	cipher_blks[1]  = gen_logging_blk((block*)(log_msg+12),(counter+2)); 
	cipher_blks[2]  = gen_logging_blk((block*)(log_msg+26),(counter+3)); 
	cipher_blks[3]  = gen_logging_blk((block*)(log_msg+40),(counter+4)); 
	AES_ECB_4(cipher_blks, sched, sign_keys);
}


static void cmpt_2_blks(block *cipher_blks, uint16_t counter, const char *log_msg, const block *sched, block sign_keys)
{
	if(counter){		
		cipher_blks[0]  = gen_logging_blk((block*)(log_msg),(counter+1)); //Not the first block
	}else{//contains the first block
		cipher_blks[0]  = _mm_srli_si128(_mm_loadu_si128((block*)log_msg), 2);
		cipher_blks[0]  = _mm_insert_epi16(cipher_blks[0], (counter+1), 0);
	}
	cipher_blks[1]  = gen_logging_blk((block*)(log_msg+12),(counter+2)); 
	cipher_blks[0] =_mm_xor_si128(cipher_blks[0], sign_keys); 
	cipher_blks[1] =_mm_xor_si128(cipher_blks[1], sign_keys); 
	AES_ECB_2(cipher_blks,sched);
}


static void cmpt_a_blk(block* cipher_blk, uint16_t counter, const char *log_msg, const block *sched, block sign_keys)
{	
	if(counter){
			*cipher_blk = _mm_loadu_si128((block*)log_msg);//Not the first block
	}else{//it is the first block
			*cipher_blk = _mm_srli_si128(_mm_loadu_si128((block*)log_msg), 2);//the first block
	}
	*cipher_blk = _mm_insert_epi16(*cipher_blk, counter+1, 0);
	/*AES Preround */
	*cipher_blk =_mm_xor_si128(*cipher_blk, sign_keys);
	aes_single(cipher_blk, sched);
}

/*Initial*/

static void crypto_int(void)
{
	block s_0, mask;
	block init_pair[2];
	block * sched;
	get_random_bytes(&s_0, sizeof(block));/*initial State */
	
	kernel_fpu_begin();	
	
	AES_128_Key_Expansion(aeskey,&const_aeskey); //inital aes round keys
	init_pair[0] = zero_block();/*0 for updatting state*/
	init_pair[1] = _mm_setr_epi32(0x0001, 0x0000, 0x0000, 0x0000);/*1 for updatting key*/
	sched = ((block *)(const_aeskey.rd_key)); 
	mask =xor_block(s_0, sched[0]);
	init_pair[0] = xor_block(init_pair[0], mask);
	init_pair[1] = xor_block(init_pair[1], mask);
	AES_ECB_2(init_pair, sched);
	current_state = xor_block(init_pair[0], s_0);
	current_key = xor_block(init_pair[1], s_0);

	kernel_fpu_end();
}
void crypto_int_all(void)
{
	block s_0, mask;
	block init_pair[2];
	block * sched;
	get_random_bytes(&s_0, sizeof(block));/*initial State */
	
	kernel_fpu_begin();	
	
	// 初始化QuickLog需要的密钥
	AES_128_Key_Expansion(aeskey,&const_aeskey); //inital aes round keys
	init_pair[0] = zero_block();/*0 for updatting state*/
	init_pair[1] = _mm_setr_epi32(0x0001, 0x0000, 0x0000, 0x0000);/*1 for updatting key*/
	sched = ((block *)(const_aeskey.rd_key)); 
	mask =xor_block(s_0, sched[0]);
	init_pair[0] = xor_block(init_pair[0], mask);
	init_pair[1] = xor_block(init_pair[1], mask);
	AES_ECB_2(init_pair, sched);
	current_state = xor_block(init_pair[0], s_0);
	current_key = xor_block(init_pair[1], s_0);

	// 初始化LightMAC需要的密钥
	get_random_bytes(&light_current_key, sizeof(block));
	get_random_bytes(&light_current_state, sizeof(block));

	kernel_fpu_end();
}

/**  
* MAC, signing a log message and updating the signing-key & state
* Input @log_msg: a log data,  
        @msg_len: the length of the log data 
* Computing block format: a block(16 bytes) contains "<i>||M_i",  
*                         2 bytes counter(<i>) and 14 bytes log data(M_i)
* Output: T(64-byte tag)
**/ 
// Even Mansour 来更新密钥
static __u64 mac_core( const char *log_msg, const int msg_len)
{
	block mask, cipher_blks[8], tag_blks[3];
	unsigned char my_pad[16];
	__u64 out_tmp[2];
	// sched是固定的AES的key，长度为11个block
	register block * sched = ((block *)(const_aeskey.rd_key)); // 11个block长度大小
	register block * aes_blks = cipher_blks;
	block *pad_zeros;
	uint16_t remaining, counter, *pad_header;
	
	remaining = (uint16_t)msg_len;
	counter =0;
	pad_header = ((uint16_t*)(my_pad));	
	pad_zeros = ((block *)(my_pad));

	// 异或全0，等于自身，为什么还要异或
	mask = _mm_xor_si128(sched[0], current_key);//xor the signing key with the aes public key
	tag_blks[2] = _mm_loadu_si128(&current_key);  // 用key来初始化结果

	// 每一个block 128 = 16 * 8 
	// 有效消息长度: 14 * 8 = 112
	if(remaining>=112)//start 8 blocks parallel computing 
	{
		// ？？？？？
		cipher_blks[0]  = _mm_srli_si128(_mm_loadu_si128((block*)log_msg), 2); // 读取一个block，然后向右移动两个字节
		cipher_blks[0]  = _mm_insert_epi16(cipher_blks[0], counter+1, 0); // 第一个块中的0，用counter+1替换
		gen_7_blks(cipher_blks,log_msg,counter); // 这7个块的counter分别替换的是哪里的内容, 前两个字节被换了
		AES_ECB_8(cipher_blks,sched, mask); // mask用于初始异或每一个块
		tag_8_xor(tag_blks,cipher_blks); // cipher_blks 8个块的结果异或，最终结果放在tag_blks[2]
		counter +=8;
		log_msg +=110;/*112-byte computed, apply 110-byte, leaving 2-byte overwrote by counter*/	// 12 + 14 * 7 = 110
		remaining -= 112; // 为什么日志只处理了110，但是这里却减了112
		while(remaining >= 112){	
			cipher_blks[0]  = gen_logging_blk((block*)log_msg, counter+1); 
			gen_7_blks(cipher_blks,log_msg,counter);
			AES_ECB_8(cipher_blks,sched, mask);
			// 最终结果的异或
			tag_8_xor(tag_blks,cipher_blks);/*)Xor each block*/
			counter += 8;
			log_msg += 110;
			remaining -= 112;
		}
	}//end of nblks
	
	if(remaining >=56){//4-block, 4*14=56 bytes log data
		cmpt_4_blks(aes_blks,counter, log_msg, sched, mask);
		tag_blks[0] = xor_block( xor_block(cipher_blks[0], cipher_blks[1]), xor_block(cipher_blks[2], cipher_blks[3]));  
		tag_blks[2] = xor_block(tag_blks[2], tag_blks[0]);
		remaining -= 56;
		counter +=4;
		log_msg +=54;/*56-byte computed, apply 54-byte, leaving 2-byte overwrote by counter*/
	}
	if (remaining >= 28) {//2-block, 2*14=28 bytes log data
		cmpt_2_blks(aes_blks, counter, log_msg, sched, mask);
		//AES_ECB_2(aes_blks,sched);
		tag_blks[2] = xor_block(xor_block(cipher_blks[0], cipher_blks[1]), tag_blks[2]); 
		remaining -= 28;
		counter +=2;
		log_msg +=26;/*28-byte computed, apply 26-byte, leaving 2-byte overwrote by counter*/
	}
	if (remaining >= 14) {//1-block 14 bytes log data
		cmpt_a_blk(&aes_blks[0],counter, log_msg, sched, mask);
		tag_blks[2] = xor_block(tag_blks[2], cipher_blks[0]);
		remaining -= 14;
		counter +=1;
		log_msg +=12;/*14-byte computed, apply 12-byte, leaving 2-byte overwrote by counter*/
	}
#if 1
	if (remaining){//last block + generating new key
		if (counter)  log_msg +=2;  // 不是第一个块, log_msg向右移动两个字节？？？？
		counter += (14-remaining); // 位置编码
		* pad_zeros = zero_block();
		* pad_header = counter;
		memcpy(&my_pad[2], log_msg, remaining); // 0,1 放的是位置编码
		cipher_blks[0] = xor_block( mask, *(block*)my_pad);  // key异或上原始内容
		cipher_blks[1] = xor_block(current_state, sched[0]);  /*0 for updatting state*/
		cipher_blks[2] = xor_block(cipher_blks[1], _mm_setr_epi32(0x0001, 0x0000, 0x0000, 0x0000)); /*1 for updatting key*/
		AES_ECB_3(cipher_blks, sched);
		tag_blks[2] = xor_block(cipher_blks[0], tag_blks[2]); // 拿到最终结果
		current_key = xor_block(cipher_blks[2], current_state);
		current_state = xor_block(cipher_blks[1], current_state);
	}else{
		// 直接更新state && key
		//pr_info("no remaining!");
		cipher_blks[0] = xor_block(current_state, sched[0]);/*0 for updatting state*/
		cipher_blks[1] = xor_block(cipher_blks[0], _mm_setr_epi32(0x0001, 0x0000, 0x0000, 0x0000));/*1 for updatting key*/
		AES_ECB_2(cipher_blks, sched);
		current_key = xor_block(cipher_blks[1], current_state);
		current_state = xor_block(cipher_blks[0], current_state);
	}
#endif
	_mm_store_si128((block*)out_tmp, tag_blks[2]); // 只要前64位作为输出

	return (out_tmp[0]);
}


static void light_parallel_4_blks(block *cipher_blks, uint16_t counter, const char *log_msg, const block *rounds_keys)
{
	cipher_blks[0]  = gen_logging_blk((block*)(log_msg),(counter+1)); 
	cipher_blks[1]  = gen_logging_blk((block*)(log_msg+14),(counter+2)); 
	cipher_blks[2]  = gen_logging_blk((block*)(log_msg+28),(counter+3)); 
	cipher_blks[3]  = gen_logging_blk((block*)(log_msg+42),(counter+4)); 
	LIGHT_AES_ECB_4(cipher_blks, rounds_keys);
}
static void light_parallel_2_blks(block *cipher_blks, uint16_t counter, const char *log_msg, const block *rounds_keys)
{
	cipher_blks[0]  = gen_logging_blk((block*)(log_msg),(counter+1)); 
	cipher_blks[1]  = gen_logging_blk((block*)(log_msg+14),(counter+2)); 
	LIGHT_AES_ECB_2(cipher_blks, rounds_keys);
}
static void light_parallel_1_blks(block *cipher_blks, uint16_t counter, const char *log_msg, const block *rounds_keys)
{
	cipher_blks[0]  = gen_logging_blk((block*)(log_msg),(counter+1)); 
	light_aes_single(cipher_blks[0], rounds_keys);
}
/**  
* MAC, signing a log message and updating the signing-key & state
* Input @log_msg: a log data,  
        @msg_len: the length of the log data 
* Computing block format: a block(16 bytes) contains "<i>||M_i",  
*                         2 bytes counter(<i>) and 14 bytes log data(M_i)
* Output: T(64-byte tag)
**/ 
// Even Mansour 来更新密钥
static __u64 light_mac_with_tradtional_mac( const char *log_msg, const int msg_len, const block* rounds_keys)
{
	uint16_t remaining = (uint16_t)msg_len;
	block cipher_blks[8]; // 存放待加密的日志原文，最多可8路并行加密
	block tag_blks[3]; // 最终结果存放
	tag_blks[2] = xor_block(tag_blks[2], tag_blks[2]); //初始化为0
	uint8_t counter = 0; // 分组块的编码
	uint8_t paylad_len = 14; // 块长度为16 * 8 = 128， 前两个字节放位置编码，后面的是日志消息

	while(remaining >= (paylad_len * 8)){
		// 8 路并行
		light_gen_8_blks(cipher_blks, log_msg, counter);
		LIGHT_AES_ECB_8(cipher_blks, rounds_keys);
		tag_8_xor(tag_blks,cipher_blks); //cipher_blks 8个块的结果异或，最终结果放在tag_blks[2], 包含历史结果的更新

		log_msg += paylad_len * 8;
		remaining -= paylad_len * 8;
		counter = counter + 8;
	}
	if(remaining >= (paylad_len * 4)){
		// 剩下的内容可以四路并行
		light_parallel_4_blks(cipher_blks, counter, log_msg, rounds_keys);
		// light_gen_4_blks(cipher_blks, log_msg, counter);
		// LIGHT_AES_ECB_4(cipher_blks, rounds_keys);
		tag_blks[0] = xor_block( xor_block(cipher_blks[0], cipher_blks[1]), xor_block(cipher_blks[2], cipher_blks[3]));  
		tag_blks[2] = xor_block(tag_blks[2], tag_blks[0]);
		log_msg += paylad_len * 4;
		remaining -= paylad_len * 4;
		counter = counter + 4;
	}
	if (remaining >= 28) {
		// 剩下的内容可以两路并行
		light_parallel_2_blks(cipher_blks, counter, log_msg, rounds_keys);
		// light_gen_2_blks(cipher_blks, log_msg, counter);
		// LIGHT_AES_ECB_2(cipher_blks, rounds_keys);
		tag_blks[2] = xor_block(xor_block(cipher_blks[0], cipher_blks[1]), tag_blks[2]); 
		log_msg += paylad_len * 2;
		remaining -= paylad_len * 2;
		counter = counter + 2;
	}

	if (remaining >= 14) {
		// 剩下的至少可以构成1个块
		light_parallel_1_blks(cipher_blks, counter, log_msg, rounds_keys);
		// cipher_blks[0]  = gen_logging_blk((block*)(log_msg),(counter+1));
		// light_aes_single(cipher_blks[0], rounds_keys);
		tag_blks[2] = xor_block(tag_blks[2], cipher_blks[0]);
		remaining -= paylad_len;
		counter +=1;
		log_msg +=paylad_len;/*14-byte computed, apply 12-byte, leaving 2-byte overwrote by counter*/
	}

unsigned char my_pad[16];
#if 1
	if (remaining){//last block + generating new key
		// 剩下的不足以构成一个块，用10*补足
		memcpy(my_pad, log_msg, remaining); // 0,1 放的是位置编码
		my_pad[remaining] = '1';
		for(int i = remaining+1;i < 16;i++){
            my_pad[i] = '0';
        }
		tag_blks[2] = xor_block(tag_blks[2], *(block*)my_pad);
	}else{
		// 直接更新state && key
		//pr_info("no remaining!");
	}
#endif
	// 更新密钥
	cipher_blks[0] = xor_block(light_current_state, _mm_setr_epi32(0x0000, 0x0000, 0x0000, 0x0000));/*0 for updatting state*/
	cipher_blks[1] = xor_block(cipher_blks[0], _mm_setr_epi32(0x0001, 0x0000, 0x0000, 0x0000));/*1 for updatting key2*/
    light_current_key = xor_block(cipher_blks[1], light_current_state);
	light_current_state = xor_block(cipher_blks[0], light_current_state);

	__u64 out_tmp[2];
	_mm_store_si128((block*)out_tmp, tag_blks[2]); // 只要前64位作为输出
	return (out_tmp[0]);
}




/**  
* QuickLog2: updating the tag, signing-key & state
* Input @log_msg: a log data, @msg_len: the length of the data
* Computing block format: a block(16 bytes) contains "<i>||M_i",  
*                         2 bytes counter(<i>) and 14 bytes log data(M_i)
* 
**/
static void mac_core_2(const char *log_msg, const int msg_len)
{
	block mask, cipher_blks[8], tag_blks[3];
	unsigned char my_pad[16];

	register block * sched = ((block *)(const_aeskey.rd_key)); 
	register block * aes_blks = cipher_blks;
	block *pad_zeros;
	uint16_t remaining, counter, *pad_header;
	
	remaining = (uint16_t)msg_len;
	counter =0;
	pad_header = ((uint16_t*)(my_pad));	
	pad_zeros = ((block *)(my_pad));

	
	mask = _mm_xor_si128(sched[0], current_key);//xor the signing key with the aes public key
	tag_blks[2] = _mm_loadu_si128(&current_key);

	if(remaining>=112)//start 8 blocks parallel computing 
	{
		cipher_blks[0]  = _mm_srli_si128(_mm_loadu_si128((block*)log_msg), 2); 
		cipher_blks[0]  = _mm_insert_epi16(cipher_blks[0], counter+1, 0);
		gen_7_blks(cipher_blks,log_msg,counter);
		AES_ECB_8(cipher_blks,sched, mask);
		tag_8_xor(tag_blks,cipher_blks);
		counter +=8;
		log_msg +=110;/*112-byte computed, apply 110-byte, leaving 2-byte overwrote by counter*/	
		remaining -= 112;
		while(remaining >= 112){	
			cipher_blks[0]  = gen_logging_blk((block*)log_msg, counter+1); 
			gen_7_blks(cipher_blks,log_msg,counter);
			AES_ECB_8(cipher_blks,sched, mask);
			tag_8_xor(tag_blks,cipher_blks);/*)Xor each block*/
			counter += 8;
			log_msg += 110;
			remaining -= 112;
		}
	}//end of nblks
	
	if(remaining >=56){//4-block, 4*14=56 bytes log data
		cmpt_4_blks(aes_blks,counter, log_msg, sched, mask);
		tag_blks[0] = xor_block( xor_block(cipher_blks[0], cipher_blks[1]), xor_block(cipher_blks[2], cipher_blks[3]));  
		tag_blks[2] = xor_block(tag_blks[2], tag_blks[0]);
		remaining -= 56;
		counter +=4;
		log_msg +=54;/*56-byte computed, apply 54-byte, leaving 2-byte overwrote by counter*/
	}
	if (remaining >= 28) {//2-block, 2*14=28 bytes log data
		cmpt_2_blks(aes_blks, counter, log_msg, sched, mask);
		//AES_ECB_2(aes_blks,sched);
		tag_blks[2] = xor_block(xor_block(cipher_blks[0], cipher_blks[1]), tag_blks[2]); 
		remaining -= 28;
		counter +=2;
		log_msg +=26;/*28-byte computed, apply 26-byte, leaving 2-byte overwrote by counter*/
	}
	if (remaining >= 14) {//1-block 14 bytes log data
		cmpt_a_blk(&aes_blks[0],counter, log_msg, sched, mask);
		tag_blks[2] = xor_block(tag_blks[2], cipher_blks[0]);
		remaining -= 14;
		counter +=1;
		log_msg +=12;/*14-byte computed, apply 12-byte, leaving 2-byte overwrote by counter*/
	}

	if (remaining){//last block + generating new key
		if (counter)  log_msg +=2;
		counter += (14-remaining);
		* pad_zeros = zero_block();
		* pad_header = counter;
		memcpy(&my_pad[2], log_msg, remaining);
		cipher_blks[0] = xor_block( mask, *(block*)my_pad);
		cipher_blks[1] = xor_block(current_state, sched[0]);
		cipher_blks[2] = xor_block(cipher_blks[1], _mm_setr_epi32(0x0001, 0x0000, 0x0000, 0x0000));
		AES_ECB_3(cipher_blks, sched);
		tag_blks[2] = xor_block(cipher_blks[0], tag_blks[2]);
		current_key = xor_block(cipher_blks[2], current_state);
		current_state = xor_block(cipher_blks[1], current_state);
		q2_tag = xor_block(tag_blks[2], q2_tag );	
	}else{
		//pr_info("no remaining!\n");
		cipher_blks[0] = xor_block(current_state, sched[0]);/*0 for updatting state*/
		cipher_blks[0] = xor_block(cipher_blks[1], _mm_setr_epi32(0x0001, 0x0000, 0x0000, 0x0000));/*1 for updatting key*/
		AES_ECB_2(cipher_blks, sched);
		current_key = xor_block(cipher_blks[1], current_state);
		current_state = xor_block(cipher_blks[0], current_state);
		q2_tag = xor_block(tag_blks[2], q2_tag );	
	}
}


#undef gen_7_blks
#undef prernd_8
#undef prernd_4
#undef tag_8_xor
#undef enc_8
#undef enc_4
#undef enc_3
#undef enc_2
#undef aes_single
#undef AES_ECB_2
#undef AES_ECB_3
#undef AES_ECB_4
#undef AES_ECB_8


//****************median function*************************
static int compare(const void* a, const void* b)
{
    unsigned long long arg1 = *(unsigned long long *)a;
    unsigned long long  arg2 = *(unsigned long long *)b;
 
    if (arg1 < arg2) return -1;
    if (arg1 > arg2) return 1;
    return 0;
}
 
unsigned long long median(size_t n, unsigned long long * x) {
    //unsigned long long temp;
    sort(x, n, sizeof(unsigned long long), &compare, NULL);

    if(n%2==0) {
        // if there is an even number of elements, return mean of the two elements in the middle
        return ((x[n/2] + x[n/2 - 1]) / 2);
    } else {
        // else return the element in the middle
        return  x[n/2];
    }
}
//**************************KennyLogging Part***************************************
// Sources:
// Riccardo Paccagnella,Kevin Liao, Dave Tian, and Adam Bates. 
// Logging to the danger zone: Race condition attacks and defenses on system audit frameworks. In CCS 2020, pages 1551–1574, 2020.
// https://bitbucket.org/sts-lab/kennyloggings/src/master/kernel-module/
void erase_from_memory(void *pointer, size_t size_data)
{
	volatile uint8_t *p = pointer;
	while (size_data--)
		*p++ = 0;
}


static u64 sign_event(char *log_msg, siphash_key_t first_key,size_t key_len, size_t log_msg_len)
{
	// size_t log_msg_len = strlen(log_msg);
	u64 integrity_proof;

	// Generate the integrity proof with the current key
	integrity_proof = siphash(log_msg, log_msg_len, &first_key);

	return integrity_proof;
}



//---------------------------------------------------------------------------------------
//endregion
void print_block(block blk)
{
    uint16_t *val = (uint16_t*) &blk; 
    pr_info("Numerical: %i %i %i %i %i %i %i %i ", 
      val[0], val[1], val[2], val[3], val[4], val[5], 
      val[6], val[7]); 
}
void print_str(char* str,int len)
{
	uint8_t *val = (uint8_t*)str;

    // uint16_t *val = (uint16_t*) &var;//can also use uint32_t instead of 16_t
	pr_info("Numerical:");
	for(int i = 0;i < len;i++){
		pr_info("i= %d, val = %d ", i, val[i]);
	}
	pr_info("");
}

/**
 * 单次简化后的AES和传统AES效率的对比
*/
void test_aes_traditional_simplified(void){
    // 初始化日志
	char *str; 
	int len = 10240;
	str = kmalloc(len, GFP_KERNEL);
	memset(str,'a',(len));

    char* log_msg = str;
    block cipher_blks[len/16];
    int blk_cnt = 0; // 先测量加密10个块的数据
    int remaining = len;
    while(remaining >= 16){ // 不考虑位置编码的占比，一个块长度为 16bytes * 8bits
        cipher_blks[blk_cnt++] = _mm_loadu_si128((const __m128i*)log_msg);
        log_msg += 16;
        remaining -= 16;
    }
    unsigned long long  start_time, end_time, simplified_time = 0, traditional_time = 0; 
    // 1151749284016177
    unsigned long long test_rounds = 100;
    // 简化的AES
    register block * const_zero_rounds_keys = ((block *)(const_aeskey.rd_key)); // 11个block长度大小
    msleep(100);
    start_time = ktime_get_ns();
    for(unsigned long long i = 0;i < test_rounds;i++){
        light_aes_single(cipher_blks[i%blk_cnt], const_zero_rounds_keys);
        // msleep(100);
    }
    end_time = ktime_get_ns();
    simplified_time += end_time - start_time;
    simplified_time /= test_rounds;
    pr_info("-[ simplified AES]-: time =%llu ns, start =%llu ns, end =%llu ns\n", simplified_time, start_time, end_time);

    // 标准的AES
    block user_key;
    block rounds_keys[11]; // 轮密钥
    get_random_bytes(&user_key, sizeof(block));
    // aes128_load_key_enc_only(&user_key, rounds_keys); // 根据user_key生成11个轮密钥
    msleep(100);
    start_time = ktime_get_ns();
    for(unsigned long long i = 0;i < test_rounds;i++){
        aes128_load_key_enc_only(&user_key, rounds_keys); // 根据user_key生成11个轮密钥
        light_aes_single(cipher_blks[i%blk_cnt], rounds_keys);
        // msleep(100);
    }
    end_time = ktime_get_ns();
    traditional_time += end_time - start_time;

    traditional_time /= test_rounds;
    pr_info("-[ traditional AES]-: time =%llu ns, start =%llu ns, end =%llu\n", traditional_time, start_time, end_time);
}

void temp_aes_traditional(void){
    // 初始化日志
	char *str; 
	str = kmalloc(10240, GFP_KERNEL);
	memset(str,'a',(8192));

    char* log_msg = str;
    block cipher_blks[100];
    int blk_cnt = 0;
    int remaining = 1024;
    while(remaining >= 16){ // 不考虑位置编码的占比，一个块长度为 16bytes * 8bits
        cipher_blks[blk_cnt++] = _mm_loadu_si128((const __m128i*)log_msg);
        log_msg += 16;
        remaining -= 16;
    }
    
    // 标准的AES
    block user_key;
    get_random_bytes(&user_key, sizeof(block));
    pr_info("get_random_bytes results :");
    print_block(user_key);
    for(int i = 0;i < 10;i++){
        pr_info("====================origin block content i:%d============== ", i);
        print_block(cipher_blks[i]);
        pr_info("====================origin block content i:%d============== ", i);
        // get_random_bytes(&user_key, sizeof(block));
        // pr_info("get_random_bytes results :");
        // print_block(user_key);
        block rounds_keys[11]; // 轮密钥
        aes128_load_key_enc_only(&user_key, rounds_keys); // 根据user_key生成11个轮密钥
        for(int j = 0;j < 11;j++){
            pr_info("round key j:%d ", j);
            print_block(rounds_keys[j]);
        }
        light_aes_single(cipher_blks[i], rounds_keys);
        pr_info("====================aes block result i:%d============== ", i);
        print_block(cipher_blks[i]);
        pr_info("====================aes block result i:%d============== ", i);
    }
}

/**
 * QuickLog 和 LightMAC对比
 * QuickLog使用简化后的AES，同使用LightMAC架构+传统AES签名日志消息的效率对比
 * 密钥，实时更新，唯一大的区别是，QuickLog使用的是简化版AES，LightMAC使用的是传统AES；
 * 目标：在可接受的性能开销（100ns内）内，获得更好的安全性和可用性
 * 多出来的时间，实际上就是AES轮密钥更新的时间，实际本身二者加密的耗时并没有太大差异
*/
void sign_benchmarking_quicklog_lightmac(void){
	// 初始化日志内容
	char *str; 
	str = kmalloc(len, GFP_KERNEL);
	memset(str,'a',(len));

	int test_rounds = 1000;
	unsigned long long  start_time, end_time, quicklog_time = 0, lightmac_time = 0;
	__u64  sign_tag;
	// QuickLog
	msleep(100);
	start_time = ktime_get_ns();
	for(int i = 0;i < test_rounds;i++){
		kernel_fpu_begin();
		sign_tag = mac_core(str, len);
		kernel_fpu_end();
	}
	end_time = ktime_get_ns();
	quicklog_time = end_time - start_time;
	quicklog_time /= test_rounds;
	quicklog_time += appd_tag_to_log_time;
	pr_info("-[ quicklog_time]-: time =%llu ns, start =%llu ns, end =%llu ns\n", quicklog_time, start_time, end_time);

	// LightMAC
	msleep(100);
	block rounds_keys[11]; // 轮密钥
	start_time = ktime_get_ns();
	for(int i = 0;i < test_rounds;i++){
		kernel_fpu_begin();
		aes128_load_key_enc_only(&light_current_key, rounds_keys); // 根据user_key(light_current_key)生成11个轮密钥
		sign_tag = light_mac_with_tradtional_mac(str, len, rounds_keys);
		kernel_fpu_end();
		// msleep(100);
	}
	end_time = ktime_get_ns();
	lightmac_time = end_time - start_time;
	lightmac_time /= test_rounds;
	lightmac_time += appd_tag_to_log_time;
	pr_info("-[ lightmac_time]-: time =%llu ns, start =%llu ns, end =%llu ns\n", lightmac_time, start_time, end_time);
}
/**
 * kennyloggings 和 LightMAC对比
 * 都是预计算密钥，所以不包含密钥更新的时间
 * kennyloggings使用的是传统的MAC框架
 * LightMAC使用的是轻量级MAC框架
 * 预期是LightMAC在kennyloggings基础上，时间开销降低
*/
void sign_benchmarking_kenny_lightmac(void){
	// 初始化日志内容
	char *str; 
	str = kmalloc(len, GFP_KERNEL);
	memset(str,'a',(len));

	int test_rounds = 10000;
	unsigned long long  start_time, end_time, lightmac_time = 0, kenny_time = 0;
	__u64  sign_tag;


	// LightMAC
	register block * const_round_keys = ((block *)(const_aeskey.rd_key)); // 11个block长度大小
	msleep(100);
	start_time = ktime_get_ns();
	for(int i = 0;i < test_rounds;i++){
		kernel_fpu_begin();
		// aes128_load_key_enc_only(&light_current_key, rounds_keys); // 根据user_key(light_current_key)生成11个轮密钥
		sign_tag = light_mac_with_tradtional_mac(str, len, const_round_keys);
		kernel_fpu_end();
		// msleep(100);
	}
	end_time = ktime_get_ns();
	lightmac_time = end_time - start_time;
	lightmac_time /= test_rounds;
	lightmac_time += appd_tag_to_log_time;
	pr_info("-[ lightmac_time]-: time =%llu ns, start =%llu ns, end =%llu ns\n", lightmac_time, start_time, end_time);

	// kennyloggings
	siphash_key_t first_key;
	size_t key_len = sizeof(first_key);
	unsigned long long temp_sum_time = 0;

	msleep(100);
	for(int i = 0;i < test_rounds;i++){
		get_random_bytes(&first_key, key_len);
		start_time = ktime_get_ns();
		sign_tag = sign_event(str, first_key, key_len, len);
		end_time = ktime_get_ns();
		temp_sum_time += end_time - start_time;
	}
	kenny_time = temp_sum_time / test_rounds;
	kenny_time += appd_tag_to_log_time;
	msleep(100);
	pr_info("-[ kenny_time]-: time =%llu ns, start =%llu ns, end =%llu ns\n", kenny_time, start_time, end_time);
}

void old_benchmarking(void){
	int i, j;
	char *str; 
	unsigned long long  start_time, end_time, appd_med, kenny_med[10], quick_med[10], quick_2_med[10];
	unsigned long long  mean, q_sd, q2_sd, k_sd, sd_sum, sum;
	__u64  quick_tag, kenny_tag;
	size_t key_len;
	siphash_key_t first_key;
	struct audit_buffer *ab = audit_log_start(NULL, GFP_KERNEL, AUDIT_SYSCALL);

	key_len = sizeof(first_key);
	str = kmalloc(len, GFP_KERNEL);
    memset(str,'a',(len));

	
	pr_info("_______Starting: log size = %dB______\n", len);
	crypto_int();

	msleep(100);

	/*************************************QuickLog*************************************************/	
	//Quicklog signing a message
	for(i=0;i<10;i++){
		for(j=0;j<iteration;j++)
		{	
			start_time = ktime_get_ns();
			kernel_fpu_begin();
			quick_tag = mac_core(str, len);
			kernel_fpu_end();
			
			end_time = ktime_get_ns();
			my_time[j] = end_time - start_time;
			
		}
		
		quick_med[i] =  median(iteration,  my_time);  
		msleep(100);
	}
	sum =0;
	for(i=0;i<10;i++) sum +=quick_med[i];
	mean = (sum/10);

	// pr_info("-[QuickLog Sign]-: median time =%llu ns\n", mean);
	// return;

	sd_sum =0;
	for(i=0;i<10;i++) sd_sum +=(quick_med[i]-mean)*(quick_med[i]-mean);
	q_sd = sd_sum/10;
	q_sd = int_sqrt(q_sd);

	msleep(100);

	

/*************************************QuickLog2*************************************************/
	for(i=0;i<10;i++){
		for(j=0;j<iteration;j++)
		{	

			start_time = ktime_get_ns();

			kernel_fpu_begin();
			mac_core_2(str, len);
			kernel_fpu_end();
			
			end_time = ktime_get_ns();
			
			my_time[j] = end_time - start_time;
			
		}
		
		quick_2_med[i] =  median(iteration,  my_time);  
		msleep(100);
	}


	sum =0;
	for(i=0;i<10;i++) sum +=quick_2_med[i];
	mean = (sum/10);
	sd_sum =0;
	for(i=0;i<10;i++) sd_sum +=(quick_2_med[i]-mean)*(quick_2_med[i]-mean);
	q2_sd = sd_sum/10;
	q2_sd = int_sqrt(q2_sd);

	

	msleep(100);
	/*************************************Kennylogging *********************************/
	
	//Kennylogging signing a message
	for(i=0;i<10;i++){
	for(j=0;j<iteration;j++)
		{
			get_random_bytes(&first_key, key_len);

			start_time = ktime_get_ns();
			kenny_tag = sign_event(str, first_key, key_len, len);
			end_time = ktime_get_ns();
			my_time[j] = end_time - start_time;
			
		}
		kenny_med[i] =  median(iteration,  my_time);  

		msleep(100);
	}

	sum =0;
	for(i=0;i<10;i++) sum +=kenny_med[i];
	mean = (sum/10);
	sd_sum =0;
	for(i=0;i<10;i++) sd_sum +=(kenny_med[i]-mean)*(kenny_med[i]-mean);
	k_sd = sd_sum/10;
	k_sd = int_sqrt(k_sd);


   //Erasing Kennylogging's current key

	for(j=0;j<iteration;j++)
	{
		get_random_bytes(&first_key, key_len);

		start_time = ktime_get_ns();
		erase_from_memory(&first_key, key_len);
		end_time = ktime_get_ns();
		my_time[j] = end_time - start_time;
		
	}
	kenny_med[0] +=  median(iteration,  my_time);  

	msleep(100);


	// Appending the tag to the log message	
	audit_log_format(ab, "type=SOCKADDR msg=audit(1650461786.949:105297428)  : saddr=0100");
	
	for(j=0;j<1000;j++)
	{	

		start_time = ktime_get_ns();

		audit_log_format(ab, " p=%llx", kenny_tag);
		
		end_time = ktime_get_ns();
		
		my_time[j] = end_time - start_time;
		
	}
	appd_med = median(1000,  my_time);
	kenny_med[0] +=  appd_med;  
	quick_med[0] +=  appd_med;


	pr_info("-[QuickLog Sign]-: median time =%llu ns, standard deviation = %llu\n", quick_med[0], q_sd);
	pr_info("--[QuickLog2 Sign]--: median time =%llu ns, standard deviation = %llu\n", quick_2_med[0], q2_sd);
	pr_info("(KennyLoggings Sign): median time =%llu ns, standard deviation = %llu\n", kenny_med[0], k_sd);

	pr_info("\n-----------------------------------------------------------\n");
	msleep(20000);
}
static int __init benchmarking(void)
{
	// old_benchmarking();
	// return 0;
	pr_info("\n_______Starting: log size = %dB______\n", len);
	crypto_int_all(); // 初始化密钥
	
	// Appending the tag to the log message	
	char *str; 
	str = kmalloc(len, GFP_KERNEL);
	memset(str,'a',(len));
	siphash_key_t first_key;
	get_random_bytes(&first_key, sizeof(first_key));
 	__u64  tag = sign_event(str, first_key, sizeof(first_key), len);
	unsigned long long  start_time, end_time;
	struct audit_buffer *ab = audit_log_start(NULL, GFP_KERNEL, AUDIT_SYSCALL);

	for(int j=0;j<1000;j++)
	{	

		start_time = ktime_get_ns();
		audit_log_format(ab, " p=%llx", tag);
		end_time = ktime_get_ns();
		
		my_time[j] = end_time - start_time;
		
	}
	appd_tag_to_log_time = median(1000,  my_time);
	pr_info("-[const time]-: appd_tag_to_log time =%llu ns\n", appd_tag_to_log_time);

	// 开始对比加密时间
	// test_aes_traditional_simplified();
	sign_benchmarking_quicklog_lightmac();
	sign_benchmarking_kenny_lightmac();
    return 0;
}


static void __exit quickmod_exit(void)
{
	pr_info("Module removed:%s ", __func__);
}

module_init(benchmarking);
module_exit(quickmod_exit);

MODULE_LICENSE("GPL");