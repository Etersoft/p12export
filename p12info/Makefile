CC	= gcc
CFLAGS	= -O2 -Wall -DL_ENDIAN
OBJS	= $(C_SRCS:.c=.o)
LIBS	= crypto

C_SRCS = \
	p12info.c

%.o: %.c $(C_SRCS) Makefile
	$(CC) $(CFLAGS) -c -o $@ $<

p12info: $(OBJS)
	$(CC) -o $@ $^ $(LIBS:%=-l%)
	strip $@

clean:
	rm -f $(OBJS) p12info
