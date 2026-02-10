#include <unistd.h>
#include <string.h>

#include "util/utilities.h"

int main(void)
{
    const char msg[] = "Hello, PKCertChain!\n";

    (void)write(1, msg, sizeof(msg) - 1);

    return 0;
}
