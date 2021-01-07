#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <keystone/keystone.h>
#include <capstone/capstone.h>
#include <readline/readline.h>
#include <readline/history.h>

#include "eval.h"

ks_arch asm_arch = KS_ARCH_X86;
ks_mode asm_mode = KS_MODE_32;
cs_arch dsm_arch = CS_ARCH_X86;
cs_mode dsm_mode = CS_MODE_32;

int assemble(char* code) {
  ks_engine *ks;
  ks_err err;
  unsigned char *encode;
  size_t size, count;

  err = ks_open(asm_arch, asm_mode, &ks);
  if (err != KS_ERR_OK) {
    printf("ERROR: failed on ks_open(), quit\n");
    return -1;
  }

  if (ks_asm(ks, code, 0, &encode, &size, &count) != KS_ERR_OK) {
    printf("ERROR: ks_asm() failed & count = %lu, error = %u\n", count, ks_errno(ks));
    return -1;
  } else {
    size_t i;

    for (i = 0; i < size; i++) {
      printf("%02X ", encode[i]);
    }
    printf("\n\n");
  }

  ks_free(encode);
  ks_close(ks);
  return 0;
}

int calculate(char* expr) {
  double result;

  if(evaluate(expr, &result)) {
    printf("%g\n\n", result);
    return 0;
  } else {
    return 1;
  }
}

// these next two functions were lifted straight out of `cstool` from Capstone
static uint8_t char_to_hexnum(char c) {
  if (c >= '0' && c <= '9') {
    return (uint8_t)(c - '0');
  }

  if (c >= 'a' && c <= 'f') {
    return (uint8_t)(10 + c - 'a');
  }

  //  c >= 'A' && c <= 'F'
  return (uint8_t)(10 + c - 'A');
}

static uint8_t *preprocess(char *code, size_t *size) {
  size_t i = 0, j = 0;
  uint8_t high, low;
  uint8_t *result;

  if (strlen(code) == 0)
    return NULL;

  result = (uint8_t *)malloc(strlen(code));
  if (result != NULL) {
    while (code[i] != '\0') {
      if (isxdigit(code[i]) && isxdigit(code[i+1])) {
        high = 16 * char_to_hexnum(code[i]);
        low = char_to_hexnum(code[i+1]);
        result[j] = high + low;
        i++;
        j++;
      }
      i++;
    }
    *size = j;
  }

  return result;
}

int disassemble(char* input) {
  csh handle;
  cs_insn *insn;
  size_t count;

  if (cs_open(dsm_arch, dsm_mode, &handle) != CS_ERR_OK) {
    printf("ERROR: failed on cs_open(), quit\n");
    return -1;
  }

  uint8_t* bytes = preprocess(input, &count);

  count = cs_disasm(handle, bytes, count, 0x0, 0, &insn);
  if (count > 0) {
    size_t j;
    for (j = 0; j < count; j++) {
      printf("%s\t%s\n", insn[j].mnemonic, insn[j].op_str);
    }
    printf("\n");

    cs_free(insn, count);
  } else {
    printf("ERROR: Failed to disassemble given code!\n");
  }

  cs_close(&handle);

  return 0;
}

int mode_switch(char* input) {

  int selection1 = 0;
  int selection2 = 0;
  int selection3 = 0;

  if(input != 0 && strlen(input) > 0) {
    sscanf(input, " %d %d %d", &selection1, &selection2, &selection3);
  }

  if(selection1 == 0) {
    printf("select an arch:\n");
    printf(" 1 - X86\n");
    printf(" 2 - ARM\n");
    printf(" 3 - AArch64\n");
    printf(" 4 - MIPS\n");
    printf(" 5 - SPARC\n");
    printf("choose: ");

    scanf("%d", &selection1);
  }

  switch(selection1) {
  case 1:
    asm_arch = KS_ARCH_X86;
    dsm_arch = CS_ARCH_X86;

    if(selection2 == 0) {
      printf("select a mode:\n");
      printf(" 1 - 16-bit\n");
      printf(" 2 - 32-bit\n");
      printf(" 3 - 64-bit\n");
      printf("choose: ");
      scanf("%d", &selection2);
    }

    switch(selection2) {
    case 1:
      asm_mode = KS_MODE_16;
      dsm_mode = CS_MODE_16;
      break;
    case 2:
      asm_mode = KS_MODE_32;
      dsm_mode = CS_MODE_32;
      break;
    case 3:
      asm_mode = KS_MODE_64;
      dsm_mode = CS_MODE_64;
      break;
    default:
      printf("pick 1-3\n");
      return mode_switch(0);
    }
    break;
  case 2:
    asm_arch = KS_ARCH_ARM;
    dsm_arch = CS_ARCH_ARM;

    if(selection2 == 0) {
      printf("select a mode:\n");
      printf(" 1 - ARM mode\n");
      printf(" 2 - THUMB mode (including Thumb-2)\n");
      printf(" 3 - ARMv8 A32 encodings for ARM\n");
      printf("choose: ");
      scanf("%d", &selection2);
    }

    switch(selection2) {
    case 1:
      asm_mode = KS_MODE_ARM;
      dsm_mode = CS_MODE_ARM;
      break;
    case 2:
      asm_mode = KS_MODE_THUMB;
      dsm_mode = CS_MODE_THUMB;
      break;
    case 3:
      asm_mode = KS_MODE_V8;
      dsm_mode = CS_MODE_V8;
      break;
    default:
      printf("pick 1-3\n");
      return mode_switch(0);
    }
    break;
  case 3:
    asm_arch = KS_ARCH_ARM64;
    dsm_arch = CS_ARCH_ARM64;

    if(selection2 == 0) {
      printf("select a mode:\n");
      printf(" 1 - ARM mode\n");
      printf(" 2 - THUMB mode (including Thumb-2)\n");
      printf(" 3 - ARMv8 A32 encodings for ARM\n");
      printf("choose: ");
      scanf("%d", &selection2);
    }

    switch(selection2) {
    case 1:
      asm_mode = KS_MODE_ARM;
      dsm_mode = CS_MODE_ARM;
      break;
    case 2:
      asm_mode = KS_MODE_THUMB;
      dsm_mode = CS_MODE_THUMB;
      break;
    case 3:
      asm_mode = KS_MODE_V8;
      dsm_mode = CS_MODE_V8;
      break;
    default:
      printf("pick 1-3\n");
      return mode_switch(0);
    }
    break;
  case 4:
    asm_arch = KS_ARCH_MIPS;
    dsm_arch = CS_ARCH_MIPS;

    if(selection2 == 0) {
      printf("select a mode:\n");
      printf(" 1 - MicroMips mode\n");
      printf(" 2 - Mips III ISA\n");
      printf(" 3 - Mips32r6 ISA\n");
      printf(" 4 - Mips32 ISA\n");
      printf(" 5 - Mips64 ISA\n");
      printf("choose: ");
      scanf("%d", &selection2);
    }

    switch(selection2) {
    case 1:
      asm_mode = KS_MODE_MICRO;
      dsm_mode = CS_MODE_MICRO;
      break;
    case 2:
      asm_mode = KS_MODE_MIPS3;
      dsm_mode = CS_MODE_MIPS3;
      break;
    case 3:
      asm_mode = KS_MODE_MIPS32R6;
      dsm_mode = CS_MODE_MIPS32R6;
      break;
    case 4:
      asm_mode = KS_MODE_MIPS32;
      dsm_mode = KS_MODE_32;
      break;
    case 5:
      asm_mode = KS_MODE_MIPS64;
      dsm_mode = KS_MODE_64;
      break;
    default:
      printf("pick 1-5\n");
      return mode_switch(0);
    }
    break;
  case 5:
    asm_arch = KS_ARCH_SPARC;
    dsm_arch = CS_ARCH_SPARC;

    if(selection2 == 0) {
      printf("select a mode:\n");
      printf(" 1 - 32-bit mode\n");
      printf(" 2 - 64-bit mode\n");
      printf(" 3 - SparcV9 mode\n");
      printf("choose: ");
      scanf("%d", &selection2);
    }

    switch(selection2) {
    case 1:
      asm_mode = KS_MODE_SPARC32;
      dsm_mode = KS_MODE_32;
      break;
    case 2:
      asm_mode = KS_MODE_SPARC64;
      dsm_mode = KS_MODE_64;
      break;
    case 3:
      asm_mode = KS_MODE_V9;
      dsm_mode = KS_MODE_V9;
      break;
    default:
      printf("pick 1-3\n");
      return mode_switch(0);
    }
    break;
  default:
    printf("pick 1-5\n");
    return mode_switch(0);
  }

  if(selection3 == 0) {
    printf("select an endian-ness:\n");
    printf(" 1 - little endian\n");
    printf(" 2 - big endian\n");
    printf("choose: ");

    scanf("%d", &selection3);
  }

  switch(selection3) {
  case 1:
    asm_mode |= KS_MODE_LITTLE_ENDIAN;
    dsm_mode |= CS_MODE_LITTLE_ENDIAN;
    break;
  case 2:
    asm_mode |= KS_MODE_BIG_ENDIAN;
    dsm_mode |= CS_MODE_BIG_ENDIAN;
    break;
  default:
    printf("pick 1-2\n");
    return mode_switch(0);
  }
  return 0;
}

int main() {
  rl_bind_key('\t', rl_insert);

  printf("*** Interactive (dis)assembler ***\n");
  printf("*   Type `help` for commands.    *\n");
  printf("**********************************\n");

  char* input;
  int result;

  while(true) {
    input = readline("> ");

    if(input == NULL) goto cleanup;

    if (strlen(input) > 0) {
      add_history(input);
    }

    switch(input[0]) {
    case 0:
      break;
    case 'a': //assemble
      result = assemble(input+1);
      if(result != 0) {
        printf("failed to assemble. is a valid mode set?\n");
      }
      break;
    case 'c': //calculate
      result = calculate(input+1);
      if(result != 0) {
        printf("failed to calculate.\n");
      }
      break;
    case 'd': //disassemble
      result = disassemble(input+1);
      if(result != 0) {
        printf("failed to disassemble. is a valid mode set?\n");
      }
      break;
    case 'm': //mode switch
      result = mode_switch(input+1);
      if(result != 0) {
        printf("failed to set the mode.\n");
      }
      break;
    case 'h': //help
      printf("a <instructions> - assemble into hex bytes\n");
      printf("d <bytes> - disassemble into instructions\n");
      printf("m <arch> <mode> <endianess> - mode switch (change archs)\n");
      printf("c <expression> - evaluate a math expression\n");
      printf("x <decimal> - convert decimal to hex");
      printf("h[elp] - this help\n");
      printf("q - exit\n");
      break;
    case 'q': //quit
      goto cleanup;
      break;
    case 'x': //hexify
      result = atoi(input+1);
      printf("0x%X\n\n", result);
      break;
    default:
      printf("unknown command\n");
      break;
    }
    free(input);
  }

  cleanup:
  free(input);
  printf("\n");
  return 0;
}
