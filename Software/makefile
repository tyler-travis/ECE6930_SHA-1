all: sha1_baseline sha1_op1 sha1_op2

sha1_baseline: baselineSHA.o
	gcc -mavx -o sha1_baseline baselineSHA.o

baseline.o: baselineSHA.c
	gcc -c baselineSHA.c

sha1_op1: sha1Op1.o
	gcc -mavx -o sha1_op1 sha1Op1.o

sha1Op1.o: sha1Op1.c
	gcc -c sha1Op1.c

sha1_op2: sha1Op2.o
	gcc -mavx -o sha1_op2 sha1Op2.o

sha1Op2.o: sha1Op2.c
	gcc -c sha1Op2.c

clean:
	rm *.o
	rm sha1_baseline
	rm sha1_op1
	rm sha1_op2
