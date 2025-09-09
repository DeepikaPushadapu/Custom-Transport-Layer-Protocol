CC = gcc
CFLAGS = -Wall
LIBS = -L. -lksocket

all: libksocket.a initksocket user1 user2

run_initksocket: initksocket
	./initksocket

run_user1: user1
	./user1

run_user2: user2
	./user2

initksocket: initksocket.c libksocket.a
	$(CC) $(CFLAGS) -o $@ initksocket.c $(LIBS)

user1: user1.c libksocket.a
	$(CC) $(CFLAGS) -o $@ user1.c $(LIBS)

user2: user2.c libksocket.a
	$(CC) $(CFLAGS) -o $@ user2.c $(LIBS)

libksocket.a: ksocket.o
	ar rcs $@ ksocket.o

ksocket.o: ksocket.c ksocket.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o *.a initksocket user1 user2
	rm -f *.*.*.*_*.txt
