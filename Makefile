all: autobiu

autobiu: autobiu.c
	gcc -o autobiu autobiu.c

clean:
	rm -f autobiu autobiu.conf
