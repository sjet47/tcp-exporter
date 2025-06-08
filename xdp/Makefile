nic := eno2
CFLAGS :=

vmlinux.h: /sys/kernel/btf/vmlinux
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

tcptrace.o: tcptrace.bpf.c vmlinux.h
	clang ${CFLAGS} -target bpf -g -O2 -c -o tcptrace.o tcptrace.bpf.c

load: tcptrace.o
	sudo xdp-loader load -m skb -s xdp.tcptrace ${nic} tcptrace.o

unload:
	sudo xdp-loader unload -a ${nic}

clean:
	rm *.o
