challenge_01: ./lib/OpenSSL bin
	$(CC) -Wall ./src/challenge_01.c ./src/crypto.c -Llib -lcrypto -lssl -o bin/challenge_01

test_challenge_01: challenge_01
	./bin/challenge_01

./lib/OpenSSL:
	./build_openssl.sh

bin:
	mkdir bin

clean:
	rm -r ./bin

clean_all: clean
	rm -r ./lib
