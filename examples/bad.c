#include <stdio.h>
#include <stdlib.h>

int main()
{
    malloc(10);
    malloc(20);
    printf("hello\n");
    int *p;
    printf("%d\n", *p);
    return 0;
}
