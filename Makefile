#	Makefile

DIST	?=	ec24-thrc
XBIN	?=	xtest
CC		?=	gcc
CFLAGS	+= 	-Wall -Wextra -Ofast
#	slower instrumentation flags
#CFLAGS	+=	-Wall -Wextra -Wshadow -fsanitize=address,undefined -O2 -g 
#CFLAGS	+=	-fPIC -fprofile-arcs -ftest-coverage 

#	options
CFLAGS	+=	-DRACC_AVX2 -march=native
CFLAGS	+=	-Iinc
CSRC	+= 	$(wildcard *.c util/*.c)
OBJS	= 	$(CSRC:.c=.o)
SUFILES	= 	$(CSRC:.c=.su)
LDLIBS	+=	-lm

#	Standard Linux C compile
$(XBIN): $(OBJS)
	$(CC) $(CFLAGS) -o $(XBIN) $(OBJS) $(LDLIBS)

%.o:	%.[cS]
	$(CC) $(CFLAGS) -c $^ -o $@

#	Cleanup
obj-clean:
	$(RM) -f $(XBIN) $(OBJS) $(SUFILES) nist/*.o nist/*.su \
	*.gcov *.gcda *.gcno */*.gcov */*.gcda */*.gcno gmon.out

clean:	obj-clean
	$(RM) -f bench_*
	$(RM) -rf kat
	cd thrc-py && $(MAKE) clean

dist:	clean
	cd ..; tar cfvz $(DIST).tgz $(DIST)/*
