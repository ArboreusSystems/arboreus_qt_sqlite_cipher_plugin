// ----------------------------------------------------------
/*!
	\headerfile %{CN}
	\title
	\brief Template file files/cppheader/file.h

	\list
	\li @notice Template file classes/file.h
	\li @copyright Arboreus (http://arboreus.systems)
	\li @author Alexandr Kirilov (http://alexandr.kirilov.me)
	\li @created 15/11/2026 at 09:01:34
	\endlist
*/
// ----------------------------------------------------------

#ifndef SQLITECIPHER_SECUREMEMORY_P_H
#define SQLITECIPHER_SECUREMEMORY_P_H

// Precompiled includes

// System includes
#include <cstddef>
#include <climits>
#include <cstring>
#include <mutex>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

// Qt includes
#include <QtCore/qlogging.h>

// Application includes
#include <asqlitecipherdatamodels.h>

// Application C includes
extern "C" {
#include "sqlite3mc_amalgamation.h"
}

// Namespace
namespace ASqliteCipherSecureMemory {

// -------------------
// Makes SQLite take all of its memory from protected regions. Has to be
// called before SQLite is initialized, that is before the first connection is
// opened. Returns false if it was too late.

bool fMemoryInstall(void);

// -------------------
// Allocation from the protected regions, for the driver's own secrets.
// Returns nullptr if no memory is available.

void* fMemoryAllocate(std::size_t inSize);

// -------------------
// Zeroes and releases memory obtained from allocate().

void fMemoryRelease(void* inPointer);

// -------------------
// Overwrites memory in a way the compiler is not allowed to optimize away.

void fMemoryZeroing(void* inPointer,std::size_t inSize);

// -------------------
// Memory data info

AMemoryStats fMemoryStats();

} // namespace ASqliteCipherSecureMemory

#endif // SQLITECIPHER_SECUREMEMORY_P_H
