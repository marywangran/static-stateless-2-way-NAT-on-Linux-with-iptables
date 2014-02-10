obj-m += xt_STATIC-2-WAY-NAT.o

all: module xtlib
	@true

module:
	make -C /lib/modules/`uname -r`/build SUBDIRS=`pwd` modules
	@rm -rf *.o .tmp_versions .*.mod.o .*.o.cmd *.mod.c .*.ko.cmd Module.symvers modules.order *.oo 

xtlib:
	gcc libxt_STATIC-2-WAY-NAT.c -fPIC -shared -o libxt_STATIC-2-WAY-NAT.so  -L/usr/local/lib -lxtables
	@rm -rf *.o .tmp_versions .*.mod.o .*.o.cmd *.mod.c .*.ko.cmd Module.symvers modules.order *.oo 

clean:
	rm -rf *.ko *.o .tmp_versions .*.mod.o .*.o.cmd *.mod.c .*.ko.cmd Module.symvers modules.order *.so *.oo
