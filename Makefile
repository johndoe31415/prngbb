.PHONY: all clean test
all: prngbb-fill

CFLAGS := -Wall -Wextra -Wshadow -Wswitch -Wpointer-arith -Wcast-qual -Wstrict-prototypes -Wmissing-prototypes -Werror=implicit-function-declaration -Werror=format -Wno-unused-parameter
CFLAGS += -O3 -std=c11

LDFLAGS := `pkg-config --libs openssl`

OBJS := \
	prngbb-fill.o

test: prngbb-fill
	./prngbb-fill /dev/zero 0 256 0 40960

clean:
	rm -f $(OBJS) $(OBJS_CFG) prngbb-fill

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

prngbb-fill: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)
