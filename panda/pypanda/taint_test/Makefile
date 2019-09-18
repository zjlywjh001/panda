all: taint

CFLAGS += -m32 -g  -O0

taint: taint.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f taint
