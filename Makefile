bin/challenges/01: ./lib/OpenSSL bin/challenges
	$(CC) -Wall ./src/challenges/01.c ./src/crypto.c -Llib -lcrypto -lssl -o bin/challenges/01

bin/challenges/02: ./lib/OpenSSL bin/challenges
	$(CC) -Wall ./src/challenges/02.c ./src/crypto.c -Llib -lcrypto -lssl -o bin/challenges/02

test_challenge_01: clean bin/challenges/01
	./bin/challenges/01

test_challenge_02: clean bin/challenges/02
	./bin/challenges/02

tests: test_challenge_01 test_challenge_02

./lib/OpenSSL:
	./build_openssl.sh

bin/challenges:
	mkdir -p bin/challenges

clean:
	rm -rf ./bin

clean_all: clean
	rm -rf ./lib
