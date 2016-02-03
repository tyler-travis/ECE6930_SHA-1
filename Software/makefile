SHA1: baselineSHA.o
	gcc -mavx -o SHA1 baselineSHA.o

baseline.o: baselineSHA.c
	gcc -c baselineSHA.c

clean:
	rm *.o
	rm SHA1
