CC = gcc
CFLAGS = -Wall -O2
LIBS = -loqs -lcrypto

TARGET = pqc_tool
SRC = pqc_tool.c util.c

TEST_DIR = ../../tests

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LIBS)

# Run full test (generate + verify)
test: $(TARGET)
	./$(TARGET) gen $(TEST_DIR)/image.bin $(TEST_DIR)/image.sig $(TEST_DIR)/pubkey.bin $(TEST_DIR)/seckey.bin
	./$(TARGET) verify $(TEST_DIR)/image.bin $(TEST_DIR)/image.sig $(TEST_DIR)/pubkey.bin

# Optional: just generate
gen: $(TARGET)
	./$(TARGET) gen $(TEST_DIR)/image.bin $(TEST_DIR)/image.sig $(TEST_DIR)/pubkey.bin $(TEST_DIR)/seckey.bin

# Optional: just verify
verify: $(TARGET)
	./$(TARGET) verify $(TEST_DIR)/image.bin $(TEST_DIR)/image.sig $(TEST_DIR)/pubkey.bin

clean:
	rm -f $(TARGET)