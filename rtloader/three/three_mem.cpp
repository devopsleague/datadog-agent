// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog
// (https://www.datadoghq.com/).
// Copyright 2019-present Datadog, Inc.

// Tracking allocations in RAW python domain. This avoids the need to
// track individual pointers by using non-standard functions present
// on all supported platforms that return allocation size for a given
// pointer (see pyrawAllocSize).
//
// This explicitly calls the C allocator instead of adding layer on
// top of the built-in python allocator, to be sure that our pointers
// come from malloc and not some other kind of allocator, and are
// compatible with malloc_usable_size.

// See https://docs.python.org/3/c-api/memory.html#customize-memory-allocators

#include "three.h"

#if __linux__ || _WIN32
#    include <malloc.h>
#elif __APPLE__ || __FreeBSD__
#    include <malloc/malloc.h>
#endif

static size_t pyrawAllocSize(void *ptr)
{
#if __linux__
    return malloc_usable_size(ptr);
#elif _WIN32
    return _msize(ptr);
#elif __APPLE__ || __FreeBSD__
    return malloc_size(ptr);
#else
    return 0;
#endif
}

void Three::pyrawTrackAlloc(void *ptr)
{
    if (ptr == NULL) {
        return;
    }
    size_t size = pyrawAllocSize(ptr);
    _pymemInuse += size;
    _pymemAlloc += size;
}

void Three::pyrawTrackFree(void *ptr)
{
    if (ptr == NULL) {
        return;
    }
    size_t size = pyrawAllocSize(ptr);
    _pymemInuse -= size;
}

void *Three::pyrawMalloc(size_t size)
{
    if (size == 0) {
        size = 1;
    }
    void *ptr = malloc(size);
    pyrawTrackAlloc(ptr);
    return ptr;
}

void *Three::pyrawCalloc(size_t nelem, size_t elsize)
{
    if (nelem == 0 || elsize == 0) {
        nelem = 1;
        elsize = 1;
    }
    void *ptr = calloc(nelem, elsize);
    pyrawTrackAlloc(ptr);
    return ptr;
}

void *Three::pyrawRealloc(void *ptr, size_t size)
{
    if (size == 0) {
        size = 1;
    }
    pyrawTrackFree(ptr);
    ptr = realloc(ptr, size);
    pyrawTrackAlloc(ptr);
    return ptr;
}

void Three::pyrawFree(void *ptr)
{
    pyrawTrackFree(ptr);
    free(ptr);
}

void *Three::pyrawMallocCb(void *ctx, size_t size)
{
    return static_cast<Three *>(ctx)->pyrawMalloc(size);
}

void *Three::pyrawCallocCb(void *ctx, size_t nelem, size_t elsize)
{
    return static_cast<Three *>(ctx)->pyrawCalloc(nelem, elsize);
}

void *Three::pyrawReallocCb(void *ctx, void *ptr, size_t new_size)
{
    return static_cast<Three *>(ctx)->pyrawRealloc(ptr, new_size);
}

void Three::pyrawFreeCb(void *ctx, void *ptr)
{
    static_cast<Three *>(ctx)->pyrawFree(ptr);
}
