all:
	gcc -g -o sdt_parser sdt_parser.c -lelf
clean:
	rm -rf sdt_parser
