/*=========================================================================
*
*   The PyRISC Project
*
*   Linker script
*
*   Jin-Soo Kim
*   Systems Software and Architecture Laboratory
*   Seoul National University
*   http://csl.snu.ac.kr
*
=========================================================================*/



OUTPUT_ARCH( "riscv" )
/* >>> Our addition. <<< */
MEMORY
{
   /* qemu-system-risc64 virt machine */
   RAM (rwx)  : ORIGIN = 0x7fffff7e0000, LENGTH = 128M
}
/* >>> End of our addition. <<< */

ENTRY(_start)

SECTIONS
{
  . = 0x7fffff7e0000;
  .text.init : { *(.text.init) }
  . = ALIGN(0x1000);
  .tohost : { *(.tohost) }
  . = ALIGN(0x1000);
  .text : { *(.text) }
  PROVIDE(__stack_top = 0x7ffffffff000);
  . = 0x7fffff7ff000;
  .data : { *(.data) }
  .bss : { *(.bss) }
  _end = .;
}
