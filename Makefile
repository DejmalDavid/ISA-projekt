all:
	gcc -std=gnu99 -Wall -Wextra  -pedantic *.c -o  dns-export -lpcap
