#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    srand(0);
    printf("Allocating...\n");
    for (int c = 0; c < 10000; c++)
    {
        if (c % 100 == 0)
            printf("current allocation %d\n", c);

        int* arr = (int*)malloc(500000 * sizeof(int));
        for (int i = 0; i < 500000; i++)
        {
            arr[i] = rand();
        }
        free(arr);
    }
    
    printf("Done allocating\n");

    int* arr2 = (int*)malloc(50000 * sizeof(int));

    for (int i = 0; i < 50000; i++)
    {
        if (arr2[i] != 0)
            printf("%d\n", arr2[i]);
    }

    free(arr2);
    
    return 0;
}