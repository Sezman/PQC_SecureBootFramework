CC = gcc
CFLAGS = -Wall -O2 -Isrc -Ithird_party/pqclean

TARGET = pqc_verify

SRC = src/pqc_verify.c \
      third_party/pqclean/fips202.c \
      third_party/pqclean/ntt.c \
      third_party/pqclean/packing.c \
      third_party/pqclean/poly.c \
      third_party/pqclean/polyvec.c \
      third_party/pqclean/reduce.c \
      third_party/pqclean/rounding.c \
      third_party/pqclean/sign.c \
      third_party/pqclean/symmetric-shake.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)

clean:
	@echo "Cleaning build files..."
	rm -f $(TARGET)