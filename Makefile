all:
	gcc -std=gnu99  -Wextra  -pedantic *.c -o  dns-export -lpcap
