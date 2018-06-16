challenge_01:
	$(CC) -Wall ./src/challenge_01.c ./src/crypto.c -o bin/challenge_01

test_challenge_01: challenge_01
	./bin/challenge_01 000f10ff

