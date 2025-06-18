NIC := eno2
CFLAGS :=
KERNEL_VERSION := 5.15

vmlinux.h: /sys/kernel/btf/vmlinux
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

tcptrace.o.6.15: 6.15/vmlinux.h tcptrace.bpf.c
	clang ${CFLAGS} -DKERNEL_VERSION_6_15 -target bpf -g -O2 -c -o 6.15/tcptrace.o tcptrace.bpf.c

tcptrace.o.5.15: 5.15/vmlinux.h tcptrace.bpf.c
	clang ${CFLAGS} -DKERNEL_VERSION_5_15 -target bpf -g -O2 -c -o 5.15/tcptrace.o tcptrace.bpf.c

tcptrace.o.5.5: 5.5/vmlinux.h tcptrace.bpf.c
	clang ${CFLAGS} -DKERNEL_VERSION_5_5 -target bpf -g -O2 -c -o 5.5/tcptrace.o tcptrace.bpf.c

tcptrace.o: tcptrace.o.6.15 tcptrace.o.5.15 tcptrace.o.5.5

load: tcptrace.o
	sudo xdp-loader load -m skb -s xdp.tcptrace ${NIC} ${KERNEL_VERSION}/tcptrace.o

unload:
	sudo xdp-loader unload -a ${NIC}

clean:
	rm *.o
