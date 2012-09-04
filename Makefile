LIBNAME := blkmaker

CFLAGS := -ggdb -O0 -Wall -Werror

all: example

lib: lib$(LIBNAME).so lib$(LIBNAME)_jansson.so

example: example.o lib$(LIBNAME).so lib$(LIBNAME)_jansson.so
	$(CC) $(LDFLAGS) -o $@ $^ -ljansson -lgcrypt -Wl,-rpath,.

lib$(LIBNAME).so: blkmaker.o blktemplate.o

lib$(LIBNAME)_jansson.so: blkmaker_jansson.o

%.so:
	$(CC) -shared $(LDFLAGS) -o $@ $^

%.o: %.c *.h
	$(CC) -c -fPIC -I. $(CFLAGS) -std=c99 -o $@ $<

clean:
	rm -f *.so *.o
