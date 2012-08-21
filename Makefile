telnetenable : blowfish.c blowfish.h md5.c md5.h telnetenable.c
	cc -o telnetenable telnetenable.c blowfish.c md5.c

clean :
	rm telnetenable