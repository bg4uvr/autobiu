all: autobiu

autobiu: autobiu.c unp.h
	gcc -o autobiu autobiu.c

clean:
	rm -f autobiu autobiu.conf
