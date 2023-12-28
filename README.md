Title - Heap Memory Allocator

Description - 
This is an optimized heap memory allocator with block headers, footers, and p-bits for efficient block management. It uses immediate coalescing upon block freeing, to minimize fragmentation. 
An explicit free list is utilized to expedite block selection without scanning the entire heap, enhancing overall allocation performance.

How to run -
The following project can only be run on a linux system with a C compiler, as the header files cannot be run on windows or mac. Copy all the files on the linux system, and create a folder called "tests".
Add all the test files to this folder. Then, using the makefile, you can use the command "make runtests" in the terminal, to run the testers. You can also run indiviual tests using "make test name".
To visualize the heap structure at anytime, use the GDB debugger to see how memory is being allocated for different request sizes.
