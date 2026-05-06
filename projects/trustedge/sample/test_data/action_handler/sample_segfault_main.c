#include <stdio.h>


int main(int argc, char *argv[])
{
    printf("Sample segfault C binary.\n");
    int *a = NULL;

    for (int i = 1; i < argc; i++)
    {
        printf("argv[%d] = %s\n", i, argv[i]);
    }
    a[0] = 42;

    return 0;
}
