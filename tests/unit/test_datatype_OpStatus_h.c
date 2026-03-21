#include <assert.h>
#include "datatype/OpStatus.h"

int main(void) {
    assert(OP_NULL_PTR == 0);
    assert(OP_BUF_TOO_SMALL == 1);
    assert(OP_INVALID_INPUT == 2);
    assert(OP_SUCCESS == 3);
    return 0;
}
