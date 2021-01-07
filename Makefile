CC = gcc

all: ixa

clean:
	rm ixa

ixa: ixa.c
	${CC} -o ixa ixa.c eval.c -lkeystone -lcapstone -lstdc++ -lm -lreadline
