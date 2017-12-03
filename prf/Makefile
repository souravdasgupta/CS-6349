CC = gcc # C compiler
CFLAGS = -fPIC -Wall -Wextra -g # C flags
LDFLAGS = -lssl -lcrypto   # linking flags
RM = rm -f    # rm command
TARGET_LIB = ../build/libpre.a

DEBUGFLAGS   = -O0 -D _DEBUG
RELEASEFLAGS = -O2 -D NDEBUG -combine -fwhole-program

SRCS= $(wildcard *.c)
DEPS = $(wildcard *.h)
OBJS = $(SRCS:.c=.o)

$(TARGET_LIB): $(OBJS)
	ar -rcs -o $@ $^    # -o $@ says, put the output of the compilation in the file named on the left side of the :
	mv $(OBJS) ../build/

$(SRCS:.c=.d):%.d:%.c
	$(CC) $(CFLAGS) -MM $< >$@ $(LDFLAGS)     # the $< is the first item in the dependencies list, and the CFLAGS macro is defined as above
include $(SRCS:.c=.d)

.PHONY: clean
clean:
	-${RM} ${TARGET_LIB} ${OBJS} $(SRCS:.c=.d)