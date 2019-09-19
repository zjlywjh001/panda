nasm -f elf -F dwarf -g taint.s -o taint_asm.o && ld -m elf_i386 -o taint_asm taint_asm.o && ./taint_asm; echo $?
