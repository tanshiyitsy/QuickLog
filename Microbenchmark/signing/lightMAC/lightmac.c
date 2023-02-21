

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

static int len= 256; //generating size
module_param(len, int, S_IRUGO);

typedef __u64 block_64;
typedef __m128i block_128;
// typedef struct {block_128 rd_key[11]; } AES_KEY;
static block_128 current_key2;
static block_64 current_key1[2];
#define iteration 200000
#define test_rounds 10
#define zero_block()          _mm_setzero_si128()
#define gen_logging_blk(log,ctr) _mm_insert_epi16(_mm_loadu_si128(log), ctr, 0)
#define xor_block(x,y)        _mm_xor_si128(x,y)
// blk_cipher 和 key2 都是128位
// AES 一共 10轮，和QuickLog保持一致
// todo 这里10轮采用的key都是同一个，后期根据需要修改
// #define ek2(blk_cipher, key2)  _mm_aesenc_si128(blk_cipher, key2)
#define ek2(blk_cipher, key)                            \
    do{                                                 \
		blk_cipher = _mm_aesenc_si128(blk_cipher, key); \
		blk_cipher = _mm_aesenc_si128(blk_cipher, key); \
		blk_cipher = _mm_aesenc_si128(blk_cipher, key); \
		blk_cipher = _mm_aesenc_si128(blk_cipher, key); \
		blk_cipher = _mm_aesenc_si128(blk_cipher, key); \
		blk_cipher = _mm_aesenc_si128(blk_cipher, key); \
		blk_cipher = _mm_aesenc_si128(blk_cipher, key); \
		blk_cipher = _mm_aesenc_si128(blk_cipher, key); \
		blk_cipher = _mm_aesenc_si128(blk_cipher, key); \
		blk_cipher =_mm_aesenclast_si128(blk_cipher, key);\
	}while(0)

/**  
* light, signing a log message and updating the signing-key & state
* Input @log_msg: a log data,  
        @msg_len: the length of the log data 
* Computing block format: a block(16 bytes) contains "<i>||M_i",  
*                         2 bytes counter(<i>) and 14 bytes log data(M_i)
* Output: T(128-byte tag)

传进来的分成 64 = 8*8一个块
EK1 和Ek2 分别为PRESENT和AES
**/

// /**
//  * void present_rounds(const uint8_t *plain, const uint8_t *key, const uint8_t rounds, uint8_t *uint8_t *cipher)
//  * 80-bit secret
//  * rounds = 31时是全轮次
//  * PRESENT使用64位标记，AES使用128位
//  * 分块的时候，按照128分块，每个块分两次送入present进行加密
// */
// static block_128 mac_core(const char *log_msg, const int msg_len){
// 	uint16_t remaining = msg_len;

//     block_64  blk_64[2], blk_cipher_64[2];
//     block_128 temp_tag_128, blk_128; // temp_tag_128放置分块的中间结果, blk_128放分块结果
//     uint8_t counter = 1,rounds = 31;
//     // uint8_t *present_plain; // 8 * 8
//     uint8_t paylad_len = 14;

//     while(remaining >= paylad_len){
//         // 前两个字节放位置编码，后面的是日志消息
//         // 1. 获取14字节内容到blk_128，连接上位置编码
//         blk_128 = gen_logging_blk((block_128*)(log_msg), (counter));
//         // 2. 将blk_128 分成两个blk_64
//         _mm_store_si128((block_128*)blk_64, blk_128);
//         // 2. 将两个blk_64分别经过两次present编码, 结果放到对应的blk_cipher_64[2]
//         // void present_rounds(const uint8_t *plain, const uint8_t *key, const uint8_t rounds, uint8_t *uint8_t *cipher)
//         present_rounds((uint8_t*)&blk_64[0], (uint8_t*)&current_key1[0], rounds, (uint8_t*)&blk_cipher_64[0]);
//         present_rounds((uint8_t*)&blk_64[1], (uint8_t*)&current_key1[1], rounds, (uint8_t*)&blk_cipher_64[1]);
//         // 3. 将blk_cipher_64[2]转换为block128, 和中间结果temp_tag_128异或
//         temp_tag_128 = xor_block(temp_tag_128, ((block_128*)blk_cipher_64)[0]);
//         counter = counter + 1;
//         log_msg += 14;
//         remaining -= 14;
//     }
    
//     unsigned char my_pad[16];
//     if(remaining){
//         // pr_info("remaining=%d", remaining);
//         // 末尾拼接上10*
//         memcpy(my_pad, log_msg, remaining); // 0,1 放的是位置编码
//         my_pad[remaining] = '1';
//         for(int i = remaining+1;i < 16;i++){
//             my_pad[i] = '0';
//         }
//         // pr_info("after padding....");
//         // for(int i = 0;i < 16;i++){
//         //     pr_info("i= %d, val = %c ", i, my_pad[i]);
//         // }
//         temp_tag_128 = xor_block(temp_tag_128, *(block_128*)my_pad);
//     }else{
//         // pr_info("No remaining");
//     }
    
//     ek2(temp_tag_128, current_key2);  // 最后结果经过aes，可以截取前t位
    
//     // @todo 更新密钥
    
//     return temp_tag_128;
// }


// 块编号的r位编码(counter+i) 连接上块的内容
#define gen_8_blks(parallel_blk_128,log_msg,counter)                            \
    do{                                                                    \
        parallel_blk_128[0]  = gen_logging_blk((block*)(log_msg),(counter+1)); \
		parallel_blk_128[1]  = gen_logging_blk((block*)(log_msg+14),(counter+2)); \
		parallel_blk_128[2]  = gen_logging_blk((block*)(log_msg+28),(counter+3)); \
		parallel_blk_128[3]  = gen_logging_blk((block*)(log_msg+42),(counter+4)); \
		parallel_blk_128[4]  = gen_logging_blk((block*)(log_msg+56),(counter+5)); \
		parallel_blk_128[5]  = gen_logging_blk((block*)(log_msg+70),(counter+6)); \
		parallel_blk_128[6]  = gen_logging_blk((block*)(log_msg+84),(counter+7)); \
		parallel_blk_128[7]  = gen_logging_blk((block*)(log_msg+98),(counter+8)); \
	} while(0)



/**
 * void present_rounds(const uint8_t *plain, const uint8_t *key, const uint8_t rounds, uint8_t *uint8_t *cipher)
 * 80-bit secret
 * rounds = 31时是全轮次
 * PRESENT使用64位标记，AES使用128位
 * 分块的时候，按照128分块，每个块分两次送入present进行加密
*/
static block_128 mac_core(const char *log_msg, const int msg_len){
	uint16_t remaining = msg_len;

    block_64  blk_64[2], blk_cipher_64[2];
    block_128 temp_tag_128, blk_128; // temp_tag_128放置分块的中间结果, blk_128放分块结果
    uint8_t counter = 0,rounds = 31; // rounds 是present需要用的参数
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

    // block_128 parallel_blk_128[8];
    // // 并行
    // while (remaining >= (paylad_len * 8))
    // {
    //     gen_8_blks(parallel_blk_128, log_msg, counter);
    //     // 加密
        

    //     counter += 8;
	// 	log_msg += 112;
    //     remaining -= 112;
    // }
    
    
    unsigned char my_pad[16];
    if(remaining){
        // pr_info("remaining=%d", remaining);
        // 末尾拼接上10*
        memcpy(my_pad, log_msg, remaining); // 0,1 放的是位置编码
        my_pad[remaining] = '1';
        for(int i = remaining+1;i < 16;i++){
            my_pad[i] = '0';
        }
        // pr_info("after padding....");
        // for(int i = 0;i < 16;i++){
        //     pr_info("i= %d, val = %c ", i, my_pad[i]);
        // }
        temp_tag_128 = xor_block(temp_tag_128, *(block_128*)my_pad);
    }else{
        // pr_info("No remaining");
    }
    
    ek2(temp_tag_128, current_key2);  // 最后结果经过aes，可以截取前t位
    
    // @todo 更新密钥
    
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
/*Initial  初始化初始密钥
*/
static void crypto_int(void)
{
	
}
static int compare(const void* a, const void* b)
{
    unsigned long long arg1 = *(unsigned long long *)a;
    unsigned long long  arg2 = *(unsigned long long *)b;
 
    if (arg1 < arg2) return -1;
    if (arg1 > arg2) return 1;
    return 0;
}
/**
 * 第二个参数是 long long的数组
 * 第一个参数是它的长度
*/
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
// round_time[i] 是每i条日志消息的耗费时间，round_median[i] 是每i轮的【平均】单条日志加密时间
static unsigned long long single_msg_time[1048576], round_median[test_rounds];

void test_present_AES_time(void){
    // uint16_t remaining = msg_len;

    // block_64  blk_64[2], blk_cipher_64[2];
    // block_128 temp_tag_128, blk_128; // temp_tag_128放置分块的中间结果, blk_128放分块结果
    // uint8_t paylad_len = 14;

    block_64  blk_64[2], blk_cipher_64[2];
    block_128 temp_tag_128, blk_128; // temp_tag_128放置分块的中间结果, blk_128放分块结果

    unsigned long long  start_time, end_time;
    char *str; 
    str = kmalloc(len, GFP_KERNEL);
    memset(str,'a',(len));
    blk_128 = gen_logging_blk((block_128*)(str), (1));
    _mm_store_si128((block_128*)blk_64, blk_128);
    int temp_rounds = 100;
    uint8_t rounds = 31;

    //present
    msleep(100);
    for(int i = 0;i < temp_rounds;i++){
        start_time = ktime_get_ns();
        present_rounds((uint8_t*)&blk_64[0], (uint8_t*)&current_key1[0], rounds, (uint8_t*)&blk_cipher_64[0]);
        present_rounds((uint8_t*)&blk_64[1], (uint8_t*)&current_key1[1], rounds, (uint8_t*)&blk_cipher_64[1]);
        end_time = ktime_get_ns();
    }
    pr_info("-[LightMAC PRESENT]-: time = %llu ns\n", (end_time - start_time));

    // AES
    temp_tag_128 = xor_block(temp_tag_128, ((block_128*)blk_cipher_64)[0]);
    msleep(100);
    for(int i = 0;i < temp_rounds;i++){
        start_time = ktime_get_ns();
        ek2(temp_tag_128, current_key2);  // 最后结果经过aes，可以截取前t位
        end_time = ktime_get_ns();
    }
    // pr_info("-[LightMAC]-: median time = %llu ns, standard deviation = %llu\n", mean, q_sd);
    pr_info("-[LightMAC AES]-: time = %llu ns\n", (end_time - start_time));
}
static int __init benchmarking_lightMAC(void){    
    // char *msg1,*msg2;
    // int len1 = 28,len2 = 24; // 一个块14 个字节,msg1刚好分成两个块, msg2最后一个块需要填充10*
    // msg1 = kmalloc(len1, GFP_KERNEL);
    // msg2 = kmalloc(len2, GFP_KERNEL);
	// memset(msg1,'a',len1); 
    // memset(msg2,'b',len2); 
	// print_str(msg1, len1);
    // print_str(msg2, len2);

    // block_128 ret1 = mac_core(msg1, len1);
    // block_128 ret2 = mac_core(msg2, len2);
    // pr_info("ret1:");
    // print_block128(ret1);
    // pr_info("ret2:");
    // print_block128(ret2);

    test_present_AES_time();
    return 0;


    crypto_int();

    char *str; 
    // int len;
    str = kmalloc(len, GFP_KERNEL);
    memset(str,'a',(len));
    msleep(100);
    pr_info("\n Start .....\n");
    /*************************************LightMac*************************************************/	
    unsigned long long  start_time, end_time;
	block_128  light_tag;
    int i, j;
    for(i=0;i<test_rounds;i++){
		for(j=0;j<iteration;j++)
		{	
            /**
             * 这里的kernel_fpu_begin && kernel_fpu_end 是必须的
             * 因为 Linux 内核为了提高系统的运行速率，在任务上下文切换时，只会保存/恢复普通寄存器的值，并不包括 FPU 浮点寄存器的值，
             * 而调用 kernel_fpu_begin 主要作用是【关掉系统抢占】，
             * 浮点计算结束后调用 kernel_fpu_end 开启系统抢占，
             * 这使得代码不会被中断，从而安全的进行浮点运算，并且要求这之间的代码不能有休眠或调度操作，
             * 另外不得有嵌套的情况出现（将会覆盖原始保存的状态，然后执行 kernel_fpu_end() 最终将恢复错误的 FPU 状态）。
            */
            start_time = ktime_get_ns();
			kernel_fpu_begin();
			light_tag = mac_core(str, len);
			kernel_fpu_end();
			end_time = ktime_get_ns();
			single_msg_time[j] = end_time - start_time;
		}
		round_median[i] =  median(iteration,  single_msg_time);  
		msleep(100);
	}

    unsigned long long  mean = 0, q_sd = 0, sd_sum = 0, sum = 0;
    for(int i = 0;i < test_rounds;i++){
        sum += round_median[i];
    }
    mean = sum / test_rounds; // 平均值

    for(int i = 0;i < test_rounds;i++){
        sd_sum += (round_median[i] - mean) * (round_median[i] - mean);

    }
    q_sd = int_sqrt(sd_sum / test_rounds); // 均方差
    pr_info("-[LightMAC]-: median time = %llu ns, standard deviation = %llu\n", mean, q_sd);
    return 0;
}

static void __exit lightMAC_exit(void)
{
	pr_info("Module removed:%s \n", __func__);
}

module_init(benchmarking_lightMAC);
module_exit(lightMAC_exit);

MODULE_LICENSE("GPL");