#If no kernel directory has been specified, provide a sane default.
export KDIR ?= /lib/modules/`uname -r`/build

IVC_INCLUDE_DIR ?= /usr/local/include

PREFIX ?= "/usr"
DESTDIR ?= ""

# Compiler Flags
ccflags-y := -Iinclude/drm -Wall -Werror -Wno-declaration-after-statement -I$(IVC_INCLUDE_DIR)

# Modules to build:
obj-m += pv_display_helper.o

#
# Delegate building to the linux kernel:
#

all: modules #userspace
user: userspace

modules:
	$(MAKE) -C $(KDIR) M=$(shell pwd)

modules_install: 
	$(MAKE) -C $(KDIR) M=$(shell pwd) modules_install

userspace:
	$(CC) -Wall -Werror -fpic -shared -o libpvdisplayhelper.so pv_display_helper.c -I$(shell pwd)

backend:
	$(CC) -Wall -Werror -fpic -shared -o libpvbackendhelper.so pv_display_backend_helper.c -I$(shell pwd)

install_user: userspace
	install -D -m 644 pv_display_helper.h "${DESTDIR}${PREFIX}/include/pv_display_helper.h"
	install -D -m 644 pv_driver_interface.h "${DESTDIR}${PREFIX}/include/pv_driver_interface.h"
	install -D -m 644 data-structs/list.h "${DESTDIR}${PREFIX}/include/data-structs/list.h"
	install -D -m 644 common.h "${DESTDIR}${PREFIX}/include/common.h"
	install -D -m 755 libpvdisplayhelper.so "${DESTDIR}${PREFIX}/lib/libpvdisplayhelper.so"

install_backend: backend
	install -D -m 644 pv_display_backend_helper.h "${DESTDIR}${PREFIX}/include/pv_display_backend_helper.h"
	install -D -m 644 pv_driver_interface.h "${DESTDIR}${PREFIX}/include/pv_driver_interface.h"
	install -D -m 644 common.h "${DESTDIR}${PREFIX}/include/common.h"
	install -D -m 644 data-structs/list.h "${DESTDIR}${PREFIX}/include/data-structs/list.h"
	install -D -m 755 libpvbackendhelper.so "${DESTDIR}${PREFIX}/lib/libpvbackendhelper.so"

clean:
	rm -f *.o *.ko *.so
