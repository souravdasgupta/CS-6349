CC = gcc # C compiler
CFLAGS = -fPIC -Wall -Wextra -g # C flags
LDFLAGS = -shared  -lssl -lcrypto   # linking flags
RM = rm -f    # rm command
TARGET_LIB = ../build/libpre.so

DEBUGFLAGS   = -O0 -D _DEBUG
RELEASEFLAGS = -O2 -D NDEBUG -combine -fwhole-program

SRCS= $(wildcard *.c)
DEPS = $(wildcard *.h)
OBJS = $(SRCS:.c=.o)

$(TARGET_LIB): $(OBJS)
	$(CC) ${LDFLAGS} -o $@ $^    # -o $@ says, put the output of the compilation in the file named on the left side of the :
	mv $(OBJS) ../build/

$(SRCS:.c=.d):%.d:%.c
	$(CC) $(CFLAGS) -MM $< >$@      # the $< is the first item in the dependencies list, and the CFLAGS macro is defined as above
include $(SRCS:.c=.d)

.PHONY: clean
clean:
	-${RM} ${TARGET_LIB} ${OBJS} $(SRCS:.c=.d)