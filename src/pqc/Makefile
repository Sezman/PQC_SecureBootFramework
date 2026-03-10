CC=gcc
CFLAGS=-Wall
LIBS=-loqs -lcrypto

TARGET=pqc_verify
SRC=main.c verify_pqc.c ../common/timer.c ../common/util.c

all: $(TARGET)

$(TARGET):
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LIBS)

gen:
	$(CC) $(CFLAGS) generate_test_data.c ../common/util.c -o generate_test_data $(LIBS)

demo:
	$(CC) $(CFLAGS) ../tools/oqs_demo.c ../common/timer.c -o oqs_demo $(LIBS)

clean:
	rm -f $(TARGET) generate_test_data oqs_demo