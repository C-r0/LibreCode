nasm -f elf64 src/compiler.asm -o build/compiler.o
ld build/compiler.o -o build/compiler
./build/compiler $1 $2 $3
echo "----------------------------"
chmod +x $2
./$2
