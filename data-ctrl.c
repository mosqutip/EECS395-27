#include <stdio.h>
#include <stdlib.h>

int main(int argc, char const* argv[])
{
    int x = atoi(argv[1]);
    int y = atoi(argv[2]);
    int z = atoi(argv[3]);

    if (x == 0) {
        z = y;
    } else {
        z = x;
    }

    return z;
}
