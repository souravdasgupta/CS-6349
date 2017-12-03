CC = gcc # C compiler
RM = rm -f    # rm command
TARGET = client

DEBUGFLAGS   = -O0 -D _DEBUG
RELEASEFLAGS = -O2 -D NDEBUG -combine -fwhole-program

SRCS= $(wildcard *.c)
DEPS = $(wildcard *.h)
OBJS = $(SRCS:.c=.o)

CXXFLAGS = -O3 -o $(TARGET) -rdynamic -D_GNU_SOURCE -L../build/
LIBS = -lssl -lcrypto -lpre 

all:
	$(CC) $(SRCS) $(LIBS) $(CXXFLAGS) 

clean:
	rm -f $(TARGET) *.o