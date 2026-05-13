#ifndef PKCERTCHAIN_CONFIG_H
#define PKCERTCHAIN_CONFIG_H

#if defined(__linux__)
// Linux is supported.
#else
#error "This implementation is Linux optimized only"
#endif

#endif // PKCERTCHAIN_CONFIG_H
