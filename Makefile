CC = gcc
CFLAGS = -O2 -Wall -I./pqclean/crypto_sign/dilithium3/clean -I./pqclean/common

SRC = otp_demo.c \
      pqclean/crypto_sign/dilithium3/clean/*.c \
      pqclean/common/*.c

all: otp_demo

otp_demo: $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o otp_demo.exe
