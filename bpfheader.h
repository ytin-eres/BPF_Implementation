#define _GNU_SOURCE
#include <sys/socket.h>
#include <linux/bpf.h>
#include <unistd.h>
#include <asm/unistd_64.h> // __NR_bpf
#include <err.h>
#include <stddef.h> // offsetof
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>

#define GPLv2 "GPL v2"
#define KERNEL_4_4_NOLOCKDEP
#define ARRSIZE(x) (sizeof(x) / sizeof((x)[0]))

#define __aligned(x)    __attribute__((aligned(x)))
typedef struct { int counter; } atomic_t;
typedef struct { long __aligned(8) counter; } atomic64_t;
typedef atomic64_t atomic_long_t;
struct list_head {
  void *next, *prev;
};
struct work_struct {
  atomic_long_t data;
  struct list_head entry;
  void *func;
};

#if defined(KERNEL_4_11_NOLOCKDEP)
struct bpf_map {
  atomic_t refcnt;
  int map_type;
  int key_size;
  int value_size;
  int max_entries;
  int map_flags;
  int pages;
  void *user;
  void *ops;
  struct work_struct work;
  atomic_t usercnt;
};
#elif defined(KERNEL_4_4_NOLOCKDEP)
struct bpf_map {
  atomic_t refcnt;
  int map_type;
  int key_size;
  int value_size;
  int max_entries;
  int pages;
  void *user;
  void *ops;
  struct work_struct work;
  atomic_t usercnt;
};
#endif
struct bpf_array {
  struct bpf_map map;
  int elem_size;
  int owner_prog_type;
  bool owner_jited;
  char value[0] __aligned(8);
};
#define BPF_ARRAY_VALUE_OFFSET (offsetof(struct bpf_array, value))
struct bpf_prog {
  unsigned short  pages;          /* Number of allocated pages */
  unsigned short  jited:1,        /* Is our filter JIT'ed? */
                  locked:1,       /* Program image locked? */
                  gpl_compatible:1, /* Is filter GPL compatible? */
                  cb_access:1,    /* Is control block accessed? */
                  dst_needed:1,   /* Do we need dst entry? */
                  xdp_adjust_head:1; /* Adjusting pkt head? */
  int             type;           /* Type of BPF program */
  unsigned int    len;            /* Number of filter blocks */
  unsigned char   tag[8];
  void            *aux;           /* Auxiliary fields */
  void            *orig_prog;     /* Original BPF program */
  void            *bpf_func;
};

/* registers */
/* caller-saved: r0..r5 */
#define BPF_REG_ARG1    BPF_REG_1
#define BPF_REG_ARG2    BPF_REG_2
#define BPF_REG_ARG3    BPF_REG_3
#define BPF_REG_ARG4    BPF_REG_4
#define BPF_REG_ARG5    BPF_REG_5
#define BPF_REG_CTX     BPF_REG_6
#define BPF_REG_FP      BPF_REG_10

#define BPF_LD_IMM64_RAW(DST, SRC, IMM)         \
  ((struct bpf_insn) {                          \
    .code  = BPF_LD | BPF_DW | BPF_IMM,         \
    .dst_reg = DST,                             \
    .src_reg = SRC,                             \
    .off   = 0,                                 \
    .imm   = (__u32) (IMM) }),                  \
  ((struct bpf_insn) {                          \
    .code  = 0, /* zero is reserved opcode */   \
    .dst_reg = 0,                               \
    .src_reg = 0,                               \
    .off   = 0,                                 \
    .imm   = ((__u64) (IMM)) >> 32 })
#define BPF_LD_MAP_FD(DST, MAP_FD)              \
  BPF_LD_IMM64_RAW(DST, BPF_PSEUDO_MAP_FD, MAP_FD)
#define BPF_LDX_MEM(SIZE, DST, SRC, OFF)        \
  ((struct bpf_insn) {                          \
    .code  = BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM,\
    .dst_reg = DST,                             \
    .src_reg = SRC,                             \
    .off   = OFF,                               \
    .imm   = 0 })
#define BPF_MOV64_REG(DST, SRC)                 \
  ((struct bpf_insn) {                          \
    .code  = BPF_ALU64 | BPF_MOV | BPF_X,       \
    .dst_reg = DST,                             \
    .src_reg = SRC,                             \
    .off   = 0,                                 \
    .imm   = 0 })
#define BPF_ALU64_IMM(OP, DST, IMM)             \
  ((struct bpf_insn) {                          \
    .code  = BPF_ALU64 | BPF_OP(OP) | BPF_K,    \
    .dst_reg = DST,                             \
    .src_reg = 0,                               \
    .off   = 0,                                 \
    .imm   = IMM })
#define BPF_STX_MEM(SIZE, DST, SRC, OFF)        \
  ((struct bpf_insn) {                          \
    .code  = BPF_STX | BPF_SIZE(SIZE) | BPF_MEM,\
    .dst_reg = DST,                             \
    .src_reg = SRC,                             \
    .off   = OFF,                               \
    .imm   = 0 })
#define BPF_ST_MEM(SIZE, DST, OFF, IMM)         \
  ((struct bpf_insn) {                          \
    .code  = BPF_ST | BPF_SIZE(SIZE) | BPF_MEM, \
    .dst_reg = DST,                             \
    .src_reg = 0,                               \
    .off   = OFF,                               \
    .imm   = IMM })
#define BPF_EMIT_CALL(FUNC)                     \
  ((struct bpf_insn) {                          \
    .code  = BPF_JMP | BPF_CALL,                \
    .dst_reg = 0,                               \
    .src_reg = 0,                               \
    .off   = 0,                                 \
    .imm   = (FUNC) })
#define BPF_JMP_IMM(OP, DST, IMM, OFF)          \
  ((struct bpf_insn) {                          \
    .code  = BPF_JMP | BPF_OP(OP) | BPF_K,      \
    .dst_reg = DST,                             \
    .src_reg = 0,                               \
    .off   = OFF,                               \
    .imm   = IMM })
#define BPF_EXIT_INSN()                         \
  ((struct bpf_insn) {                          \
    .code  = BPF_JMP | BPF_EXIT,                \
    .dst_reg = 0,                               \
    .src_reg = 0,                               \
    .off   = 0,                                 \
    .imm   = 0 })
#define BPF_LD_ABS(SIZE, IMM)                   \
  ((struct bpf_insn) {                          \
    .code  = BPF_LD | BPF_SIZE(SIZE) | BPF_ABS, \
    .dst_reg = 0,                               \
    .src_reg = 0,                               \
    .off   = 0,                                 \
    .imm   = IMM })
#define BPF_ALU64_REG(OP, DST, SRC)             \
  ((struct bpf_insn) {                          \
    .code  = BPF_ALU64 | BPF_OP(OP) | BPF_X,    \
    .dst_reg = DST,                             \
    .src_reg = SRC,                             \
    .off   = 0,                                 \
    .imm   = 0 })
#define BPF_MOV64_IMM(DST, IMM)                 \
  ((struct bpf_insn) {                          \
    .code  = BPF_ALU64 | BPF_MOV | BPF_K,       \
    .dst_reg = DST,                             \
    .src_reg = 0,                               \
    .off   = 0,                                 \
    .imm   = IMM })

/* this should jump forward in the error case so that the static branch prediction
 * goes the right way (if we hit the static branch prediction for some reason)
 */
#define BPF_GOTO_EXIT_IF_R0_NULL                \
  BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0x7ff)

int bpf_(int cmd, union bpf_attr *attrs) {
  return syscall(__NR_bpf, cmd, attrs, sizeof(*attrs));
}

int array_create(int value_size, int num_entries) {
  union bpf_attr create_map_attrs = {
      .map_type = BPF_MAP_TYPE_ARRAY,
      .key_size = 4,
      .value_size = value_size,
      .max_entries = num_entries
  };
  int mapfd = bpf_(BPF_MAP_CREATE, &create_map_attrs);
  if (mapfd == -1)
    err(1, "map create");
  return mapfd;
}

int prog_load(struct bpf_insn *insns, size_t insns_count) {
  char verifier_log[100000];
  union bpf_attr create_prog_attrs = {
    .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
    .insn_cnt = insns_count,
    .insns = (uint64_t)insns,
    .license = (uint64_t)GPLv2,
    .log_level = 1,
    .log_size = sizeof(verifier_log),
    .log_buf = (uint64_t)verifier_log
  };
  int progfd = bpf_(BPF_PROG_LOAD, &create_prog_attrs);
  int errno_ = errno;
  printf("==========================\n%s==========================\n", verifier_log);
  errno = errno_;
  if (progfd == -1)
    err(1, "prog load");
  return progfd;
}


void exit_fixup(struct bpf_insn *insns, size_t arrsize) {
  int exit_idx = arrsize - 1;
  for (int i=0; i<arrsize; i++) {
    if (insns[i].code == (BPF_JMP | BPF_OP(BPF_JEQ) | BPF_K) && insns[i].off == 0x7ff) {
      printf("fixing up exit jump\n");
      insns[i].off = exit_idx - i - 1;
    }
  }
}

int create_filtered_socket_fd(struct bpf_insn *insns, size_t insns_count) {
  int progfd = prog_load(insns, insns_count);

  // hook eBPF program up to a socket
  // sendmsg() to the socket will trigger the filter
  // returning 0 in the filter should toss the packet
  int socks[2];
  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, socks))
    err(1, "socketpair");
  if (setsockopt(socks[0], SOL_SOCKET, SO_ATTACH_BPF, &progfd, sizeof(int)))
    err(1, "setsockopt");
  return socks[1];
}

/* assumes 32-bit values */
void array_set(int mapfd, uint32_t key, uint32_t value) {
  union bpf_attr attr = {
    .map_fd = mapfd,
    .key    = (uint64_t)&key,
    .value  = (uint64_t)&value,
    .flags  = BPF_ANY,
  };
  int res = bpf_(BPF_MAP_UPDATE_ELEM, &attr);
  if (res)
    err(1, "map update elem");
}

void array_set_dw(int mapfd, uint32_t key, uint64_t value) {
  union bpf_attr attr = {
    .map_fd = mapfd,
    .key    = (uint64_t)&key,
    .value  = (uint64_t)&value,
    .flags  = BPF_ANY,
  };

  int res = bpf_(BPF_MAP_UPDATE_ELEM, &attr);
  if (res)
    err(1, "map update elem");
}

void trigger_proc(int sockfd) {
  if (write(sockfd, "X", 1) != 1)
    err(1, "write to proc socket failed");
}


