CC=g++
CFLAGS= -lpcap
CFLAGS_DEBUG=-Wall -pedantic -g -fsanitize=address -DLOG_USE-COLOR -DDEBUG -lpcap
TARGET = ipk-sniffer

$(TARGET): main.o
	$(CC) $^ $(CFLAGS) -o $@

.cpp.o:
	$(CC) $(CFLAGS) $< -c

clean:
	rm *.o
	rm $(TARGET)

tar:
	tar cf xdokou14.tar Makefile main.cpp README.md manual.pdf
