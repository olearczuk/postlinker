#include <stdio.h>

void do_write(char *str) {
	printf("%s", str);
}

int main() {
	do_write("Main program [ro]\n");
	return 0;
}
