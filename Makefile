LIBS := -lcrypto -lssl
CFLAGS := -Wall

CHALSRCDIR := src/challenges
CHALBINDIR := bin/challenges
CHALSRC := $(wildcard $(CHALSRCDIR)/*.c)
CHALOBJ := $(CHALSRC:$(CHALSRCDIR)/%.c=$(CHALBINDIR)/%)

bin/challenges/%: ./lib/OpenSSL bin/challenges
	$(CC) $(CFLAGS) ./$(CHALSRCDIR)/$*.c ./src/crypto.c -Llib $(LIBS) -o $@

test_%: bin/challenges/%
	./$(CHALBINDIR)/$*

all: $(CHALOBJ)

tests: all
	$(foreach var,$(CHALOBJ),./$(var);)

./lib/OpenSSL:
	./build_openssl.sh

bin/challenges:
	mkdir -p $(CHALBINDIR)

clean:
	rm -rf ./bin

clean_all: clean
	rm -rf ./lib
