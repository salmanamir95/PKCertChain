#include <unistd.h>
#include <string.h>

#include "util/utilities.h"

int main(void)
{
    const char msg[] = "Hello, PKCertChain!\n";

    ssize_t written = write(1, msg, sizeof(msg) - 1);
    if (written < 0) {
        return 1;
    }

    return 0;
}
