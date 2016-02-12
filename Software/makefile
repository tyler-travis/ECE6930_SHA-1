all: pwck_base pwck1_O0 pwck1_O1 pwck1_O2 pwck1_O3 pwck2_O0 pwck2_O1 pwck2_O2 pwck2_O3 pwck_O0 pwck_O1 pwck_O2 pwck_O3

pwck_base: baselineSHA.c
	gcc -mavx -o pwck_base baselineSHA.c

pwck1_O0: sha1Op1.c
	gcc -O0 -mavx -o pwck1_O0 sha1Op1.c

pwck1_O1: sha1Op1.c
	gcc -O1 -fomit-frame-pointer -mavx -o pwck1_O1 sha1Op1.c

pwck1_O2: sha1Op1.c
	gcc -O2 -fomit-frame-pointer -mavx -o pwck1_O2 sha1Op1.c

pwck1_O3: sha1Op1.c
	gcc -O3 -fomit-frame-pointer -mavx -o pwck1_O3 sha1Op1.c

pwck2_O0: sha1Op2.c
	gcc -O0 -mavx -lpthread -o pwck2_O0 sha1Op2.c

pwck2_O1: sha1Op2.c
	gcc -O1 -fomit-frame-pointer -lpthread -mavx -o pwck2_O1 sha1Op2.c

pwck2_O2: sha1Op2.c
	gcc -O2 -fomit-frame-pointer -lpthread -mavx -o pwck2_O2 sha1Op2.c

pwck2_O3: sha1Op2.c
	gcc -O3 -fomit-frame-pointer -lpthread -mavx -o pwck2_O3 sha1Op2.c

pwck_O0: sha1Op.c
	gcc -O0 -mavx -lpthread -o pwck_O0 sha1Op.c

pwck_O1: sha1Op.c
	gcc -O1 -fomit-frame-pointer -lpthread -mavx -o pwck_O1 sha1Op.c

pwck_O2: sha1Op.c
	gcc -O2 -fomit-frame-pointer -lpthread -mavx -o pwck_O2 sha1Op.c

pwck_O3: sha1Op.c
	gcc -O3 -fomit-frame-pointer -lpthread -mavx -o pwck_O3 sha1Op.c

clean:
	rm pwck_base
	rm pwck1_O0
	rm pwck1_O1
	rm pwck1_O2
	rm pwck1_O3
	rm pwck2_O0
	rm pwck2_O1
	rm pwck2_O2
	rm pwck2_O3
	rm pwck_O0
	rm pwck_O1
	rm pwck_O2
	rm pwck_O3
