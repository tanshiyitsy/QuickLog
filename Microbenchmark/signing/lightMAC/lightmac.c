

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


#include "./present.h"
/**  
* MAC, signing a log message and updating the signing-key & state
* Input @log_msg: a log data,  
        @msg_len: the length of the log data 
* Computing block format: a block(16 bytes) contains "<i>||M_i",  
*                         2 bytes counter(<i>) and 14 bytes log data(M_i)
* Output: T(64-byte tag)

传进来的分成 64 = 8*8一个块
1个字节表示位置编码
**/
// PRESENT和AES实例化了LightMAC
/**
 * void present_rounds(const uint8_t *plain, const uint8_t *key, const uint8_t rounds, uint8_t *uint8_t *cipher)
 * 80-bit secret
 * rounds = 31时是全轮次
 * PRESENT使用64位标记，AES使用128位
 * 分块的时候，按照128分块，每个块分两次送入present进行加密
*/
#define gen_logging_blk(log,ctr) _mm_insert_epi16(_mm_loadu_si128(log), ctr, 0)
#define xor_block(x,y)        _mm_xor_si128(x,y)
#define ek2(blk_cipher, key2)  _mm_aesenc_si128(blk_cipher, key2)

typedef __u64 block_64;
typedef __m128i block_128;
static block_128 current_key2;
static block_64 current_key1[2];
#define zero_block()          _mm_setzero_si128()
// static block_128 Ek1(Block_128 block_128){

// }
static block_128 mac_core(const char *log_msg, const int msg_len){
	uint16_t remaining = msg_len;

    block_64  blk_64[2], blk_cipher_64[2];
    block_128 temp_tag_128, blk_128; // temp_tag_128放置分块的中间结果, blk_128放分块结果
    uint8_t counter = 1,rounds = 31;
    // uint8_t *present_plain; // 8 * 8
    uint8_t paylad_len = 14;

    while(remaining >= paylad_len){
        // 前两个字节放位置编码，后面的是日志消息
        // 1. 获取14字节内容到blk_128，连接上位置编码
        blk_128 = gen_logging_blk((block_128*)(log_msg), (counter));
        // 2. 将blk_128 分成两个blk_64
        _mm_store_si128((block_128*)blk_64, blk_128);
        // 2. 将两个blk_64分别经过两次present编码, 结果放到对应的blk_cipher_64[2]
        // void present_rounds(const uint8_t *plain, const uint8_t *key, const uint8_t rounds, uint8_t *uint8_t *cipher)
        present_rounds((uint8_t*)&blk_64[0], (uint8_t*)&current_key1[0], rounds, (uint8_t*)&blk_cipher_64[0]);
        present_rounds((uint8_t*)&blk_64[1], (uint8_t*)&current_key1[1], rounds, (uint8_t*)&blk_cipher_64[1]);
        // 3. 将blk_cipher_64[2]转换为block128, 和中间结果temp_tag_128异或
        temp_tag_128 = xor_block(temp_tag_128, ((block_128*)blk_cipher_64)[0]);
        counter = counter + 1;
        log_msg += 14;
        remaining -= 14;
    }
    
    unsigned char my_pad[16];
    if(remaining){
        pr_info("remaining=%d", remaining);
        // 末尾拼接上10*
        memcpy(my_pad, log_msg, remaining); // 0,1 放的是位置编码
        my_pad[remaining] = '1';
        for(int i = remaining+1;i < 16;i++){
            my_pad[i] = '0';
        }
        pr_info("after padding....");
        for(int i = 0;i < 16;i++){
            pr_info("i= %d, val = %c ", i, my_pad[i]);
        }
        temp_tag_128 = xor_block(temp_tag_128, *(block_128*)my_pad);
    }else{
        pr_info("No remaining");
    }
    
    temp_tag_128 = _mm_aesenc_si128(temp_tag_128, current_key2);  // 最后结果经过aes，可以截取前t位
    
    // 更新密钥
    
    return temp_tag_128;
}
void print_str(char* str,int len)
{
    pr_info("msg:");
	uint8_t *val = (uint8_t*)str;

    // uint16_t *val = (uint16_t*) &var;//can also use uint32_t instead of 16_t
	pr_info("Numerical:");
	for(int i = 0;i < len;i++){
		pr_info("i= %d, val = %d ", i, val[i]);
	}
	pr_info("\n");
}
void print_block64(block_64 var)
{
	uint8_t *val = (uint8_t*)&var;

    // uint16_t *val = (uint16_t*) &var;//can also use uint32_t instead of 16_t
	for(int i = 0;i < 8;i++){
		pr_info("i= %d, val = %d ", i, val[i]);
	}
	pr_info("\n");
}
void print_block128(block_128 var)
{
	uint8_t *val = (uint8_t*)&var;

    // uint16_t *val = (uint16_t*) &var;//can also use uint32_t instead of 16_t
	for(int i = 0;i < 16;i++){
		pr_info("i= %d, val = %d ", i, val[i]);
	}
	pr_info("\n");
}
/*Initial
初始化初始密钥
*/
static void crypto_int(void)
{
	
}

static int __init benchmarking(void){    
    char *msg1,*msg2;
    int len1 = 28,len2 = 24; // 一个块14 个字节,msg1刚好分成两个块, msg2最后一个块需要填充10*
    msg1 = kmalloc(len1, GFP_KERNEL);
    msg2 = kmalloc(len2, GFP_KERNEL);
	memset(msg1,'a',len1); 
    memset(msg2,'b',len2); 
	print_str(msg1, len1);
    print_str(msg2, len2);

    block_128 ret1 = mac_core(msg1, len1);
    block_128 ret2 = mac_core(msg2, len2);
    pr_info("ret1:");
    print_block128(ret1);
    pr_info("ret2:");
    print_block128(ret2);
    return 0;
}

static void __exit quickmod_exit(void)
{
	pr_info("Module removed:%s \n", __func__);
}

module_init(benchmarking);
module_exit(quickmod_exit);

MODULE_LICENSE("GPL");