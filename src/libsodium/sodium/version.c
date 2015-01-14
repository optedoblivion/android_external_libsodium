
#include "version.h"

const char *
sodium_version_string(void)
{
    return "version 1.0";
}

int
sodium_library_version_major(void)
{
    return 1;
}

int
sodium_library_version_minor(void)
{
    return 0;
}
