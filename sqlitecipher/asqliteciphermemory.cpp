/*
 * Protected memory for the SQLITECIPHER driver. See securememory_p.h.
 *
 * Layout
 * ------
 * Small blocks are sorted into size classes. Each class cuts its blocks from
 * regions of its own ("slabs"); a freed block is zeroed and reused for the
 * next request of that class. A slab without any block in use is unlocked and
 * given back to the system, except for one per class that is kept ready.
 *
 * A request too big for the size classes gets a region of its own, which is
 * zeroed, unlocked and given back to the system when the block is freed.
 *
 * Every block starts with a header that leads back to its slab or, for a big
 * block, holds its size.
 */

// Class header
#include "asqliteciphermemory.h"

//Namespaces
namespace ASqliteCipherSecureMemory {
namespace {

// Global variables
ASlab* gSlabsWithRoom[gClassCount];
std::mutex gMutex;
std::once_flag gSetupOnce;
std::size_t gPageSize = 4096;
bool gTriedRaisingLockLimit = false;
std::size_t gLockedBytes = 0;
std::size_t gUnlockedBytes = 0;
std::size_t gDumpableBytes = 0;


// -----------
/*!
	\fn

	Doc.
*/

void fSetup(void) {

	const long oPageSize = sysconf(_SC_PAGESIZE);
	if (oPageSize > 0) gPageSize = std::size_t(oPageSize);

#if defined(__APPLE__)
	// Apple systems cannot exclude single memory regions from a core dump,
	// so core dumps of the process are switched off as a whole.
	struct rlimit oNoCore = {0,0};
	setrlimit(RLIMIT_CORE,&oNoCore);
#endif
}


// -----------
/*!
	\fn

	Doc.
*/

std::size_t fRoundUp(std::size_t inValue, std::size_t inTo) {

	return (inValue + inTo - 1) / inTo * inTo;
}


// -----------
/*!
	\fn

	Smallest class that holds "usable" bytes; "usable" is at most MaxSmallUsable..
*/

int fClassFor(std::size_t inUsable) {

	for (int i = 0; i < gClassCount; ++i) {
		if (gClassTable.Sizes[i] >= inUsable) return i;
	}

	return gClassCount - 1;
}


// -----------
/*!
	\fn

	Doc.
*/

std::size_t fClassSize(std::uint32_t inSizeClass) {

	return inSizeClass < std::uint32_t(gClassCount) ? gClassTable.Sizes[inSizeClass] : 0;
}


// -----------
/*!
	\fn

	Asks the system for a region and applies the protections to it.
*/

char* fMapRegion(std::size_t inSize, bool* inLocked, bool* inDumpable) {

	void* oRegion = mmap(nullptr,inSize,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
	if (oRegion == MAP_FAILED) return nullptr;

	// Anti-swap.
	bool isLocked = mlock(oRegion,inSize) == 0;
	if (!isLocked && !gTriedRaisingLockLimit) {
		// Use all the locked memory the process is allowed to have.
		gTriedRaisingLockLimit = true;
		struct rlimit oLimit;
		if (getrlimit(RLIMIT_MEMLOCK,&oLimit) == 0 && oLimit.rlim_cur != oLimit.rlim_max) {
			oLimit.rlim_cur = oLimit.rlim_max;
			if (setrlimit(RLIMIT_MEMLOCK,&oLimit) == 0) isLocked = mlock(oRegion,inSize) == 0;
		}
	}

	// Anti-dump.
	bool isDumpable = true;
#if defined(MADV_DONTDUMP)
	// Android
	isDumpable = madvise(oRegion,inSize,MADV_DONTDUMP) != 0;
#elif defined(__APPLE__)
	// macOS, iOS: core dumps are switched off for the process, see setup()
	struct rlimit oCore;
	isDumpable = !(getrlimit(RLIMIT_CORE,&oCore) == 0 && oCore.rlim_cur == 0);
#endif

	*inLocked = isLocked;
	*inDumpable = isDumpable;

	return static_cast<char*>(oRegion);
}


// -----------
/*!
	\fn

	Doc.
*/

void fCountRegion(std::size_t inSize, bool inLocked, bool inDumpable, bool inAdd) {

	std::size_t& oLockCounter = inLocked ? gLockedBytes : gUnlockedBytes;
	if (inAdd) {
		oLockCounter += inSize;
		if (inDumpable) gDumpableBytes += inSize;
	} else {
		oLockCounter -= inSize;
		if (inDumpable) gDumpableBytes -= inSize;
    }
}


// -----------
/*!
	\fn

	The "has room" list of a size class.
*/

void fUnmapRegion(void* region, std::size_t size, bool locked, bool dumpable) {

	if (locked) munlock(region,size);
	fCountRegion(size,locked,dumpable,false);
	munmap(region,size);
}


// -----------
/*!
	\fn

	A large block records the size and the protection state of its region
	right behind its usable area; the region is sized to have room for that.
*/

ALargeTrailer* fLargeTrailer(AHeader* inHeader) {

	return reinterpret_cast<ALargeTrailer*>(reinterpret_cast<char*>(inHeader) + gHeaderSize + inHeader->Usable);
}


// -----------
/*!
	\fn

	The "has room" list of a size class.
*/

ASlab*& fRoomList(std::uint32_t inSizeClass) {

	return gSlabsWithRoom[inSizeClass < std::uint32_t(gClassCount) ? inSizeClass : 0];
}


// -----------
/*!
	\fn

	Doc.
*/

void fListSlab(ASlab* inSlab) {

	ASlab*& inHead = fRoomList(inSlab->SizeClass);
	inSlab->Previous = nullptr;
	inSlab->Next = inHead;
	if (inHead) inHead->Previous = inSlab;
	inHead = inSlab;
	inSlab->Listed = 1;
}


// -----------
/*!
	\fn

	Doc.
*/

void fUnlistSlab(ASlab* inSlab) {

	if (inSlab->Previous) {
		inSlab->Previous->Next = inSlab->Next;
	} else {
		fRoomList(inSlab->SizeClass) = inSlab->Next;
	}

	if (inSlab->Next) inSlab->Next->Previous = inSlab->Previous;

	inSlab->Previous = inSlab->Next = nullptr;
	inSlab->Listed = 0;
}


// -----------
/*!
	\fn

	Doc.
*/

ASlab* fNewSlab(int inSizeClass) {

	const std::size_t oBlockSize = gHeaderSize + fClassSize(std::uint32_t(inSizeClass));
	std::size_t oRegionSize = fRoundUp(gSlabHeaderSize + gBlocksPerSlab * oBlockSize,gPageSize);
	if (oRegionSize < gMinSlabSize) oRegionSize = fRoundUp(gMinSlabSize,gPageSize);
	if (oRegionSize > gMaxSlabSize) oRegionSize = fRoundUp(gMaxSlabSize,gPageSize);

	bool oLocked = false;
	bool oDumpable = true;
	char* oRegion = fMapRegion(oRegionSize,&oLocked,&oDumpable);
	if (!oRegion) return nullptr;

	fCountRegion(oRegionSize,oLocked,oDumpable,true);

	ASlab* oSlab = reinterpret_cast<ASlab*>(oRegion);
	oSlab->Previous = oSlab->Next = nullptr;
	oSlab->FreeList = nullptr;
	oSlab->RegionSize = oRegionSize;
	oSlab->SizeClass = std::uint32_t(inSizeClass);
	oSlab->Capacity = std::uint32_t((oRegionSize - gSlabHeaderSize) / oBlockSize);
	oSlab->Carved = 0;
	oSlab->InUse = 0;
	oSlab->Locked = oLocked;
	oSlab->Dumpable = oDumpable;
	oSlab->Listed = 0;

	return oSlab;
}


// -----------
/*!
	\fn

	Doc.
*/

void* fAllocateLocked(std::size_t inSize) {

	if (inSize == 0) inSize = 1;
	if (inSize > std::size_t(INT_MAX) - 2 * gPageSize) return nullptr;
	if (inSize > gMaxSmallUsable) {

		const std::size_t oUsable = fRoundUp(inSize, gAlignment);
		const std::size_t oRegionSize = fRoundUp(gHeaderSize + oUsable + sizeof(ALargeTrailer), gPageSize);
		bool oLocked = false;
		bool oDumpable = true;
		char* oRegion = fMapRegion(oRegionSize,&oLocked,&oDumpable);

		if (!oRegion) return nullptr;
		fCountRegion(oRegionSize,oLocked,oDumpable,true);

		AHeader* oHeader = reinterpret_cast<AHeader*>(oRegion);
		oHeader->SizeClass = gLargeBlock;
		oHeader->Magic = gMagic;
		oHeader->Usable = oUsable;

		ALargeTrailer* oTrailer = fLargeTrailer(oHeader);
		oTrailer->RegionSize = oRegionSize;
		oTrailer->Locked = oLocked;
		oTrailer->Dumpable = oDumpable;

		return oRegion + gHeaderSize;
	}

	const int oSizeClass = fClassFor(inSize);

	ASlab* oSlab = fRoomList(std::uint32_t(oSizeClass));
	if (!oSlab) {
		oSlab = fNewSlab(oSizeClass);
		if (!oSlab) return nullptr;
		fListSlab(oSlab);
	}

	AHeader* oHeader = nullptr;
	if (AFreeBlock* oBlock = oSlab->FreeList) {
		oSlab->FreeList = oBlock->Next;
		oBlock->Next = nullptr;
		oHeader = reinterpret_cast<AHeader*>(reinterpret_cast<char*>(oBlock) - gHeaderSize);
	} else {
		const std::size_t blockSize = gHeaderSize + fClassSize(std::uint32_t(oSizeClass));
		oHeader = reinterpret_cast<AHeader*>(reinterpret_cast<char*>(oSlab) + gSlabHeaderSize + oSlab->Carved * blockSize);
		++oSlab->Carved;
	}

	++oSlab->InUse;
	if (!oSlab->FreeList && oSlab->Carved == oSlab->Capacity) fUnlistSlab(oSlab);

	oHeader->SizeClass = std::uint32_t(oSizeClass);
	oHeader->Magic = gMagic;
	oHeader->Slab = oSlab;
	return reinterpret_cast<char*>(oHeader) + gHeaderSize;
}


// -----------
/*!
	\fn

	Doc.
*/

AHeader* fHeaderOf(void* inPointer) {

	return reinterpret_cast<AHeader*>(static_cast<char*>(inPointer) - gHeaderSize);
}


// -----------
/*!
	\fn

	Doc.
*/

void fReleaseLocked(void* inPointer) {

	AHeader* oHeader = fHeaderOf(inPointer);
	if (oHeader->Magic != gMagic) return;
	if (oHeader->SizeClass == gLargeBlock) {
		const ALargeTrailer oTrailer = *fLargeTrailer(oHeader);
		fMemoryZeroing(oHeader,oTrailer.RegionSize);
		fUnmapRegion(oHeader,oTrailer.RegionSize,oTrailer.Locked,oTrailer.Dumpable);
		return;
	}
	if (oHeader->SizeClass >= std::uint32_t(gClassCount)) return;

	ASlab* oSlab = oHeader->Slab;
	fMemoryZeroing(inPointer,fClassSize(oHeader->SizeClass));
	oHeader->Magic = gFreedMagic;

	AFreeBlock* oBlock = static_cast<AFreeBlock*>(inPointer);
	oBlock->Next = oSlab->FreeList;
	oSlab->FreeList = oBlock;
	--oSlab->InUse;

	if (!oSlab->Listed) fListSlab(oSlab);

	// Give an unused slab back, unless it is the only one of its class with
	// room: keeping that one avoids mapping and unmapping in a tight loop.
	if (oSlab->InUse == 0 && (oSlab->Previous || oSlab->Next)) {
		fUnlistSlab(oSlab);
		fUnmapRegion(oSlab,oSlab->RegionSize,oSlab->Locked,oSlab->Dumpable);
	}
}


// -----------
/*!
	\fn

	Doc.
*/

std::size_t fUsableSize(void* inPointer) {

	const AHeader* inHeader = fHeaderOf(inPointer);
	return inHeader->SizeClass == gLargeBlock ? inHeader->Usable : fClassSize(inHeader->SizeClass);
}


// -----------
/*!
	\fn

	Doc.
*/

std::size_t fRoundedSize(std::size_t inSize) {

	if (inSize == 0) inSize = 1;
	if (inSize > gMaxSmallUsable) return fRoundUp(inSize,gAlignment);
	return fClassSize(std::uint32_t(fClassFor(inSize)));
}

} // unnamed namespace


// -----------
/*!
	\fn

	Doc.
*/

void fMemoryZeroing(void* inPointer, std::size_t inSize) {

	volatile unsigned char* oPointer = static_cast<volatile unsigned char *>(inPointer);
	while (inSize--) {
		*oPointer++ = 0;
	}
}


// -----------
/*!
	\fn

	Doc.
*/

void* fMemoryAllocate(std::size_t inSize) {

	std::call_once(gSetupOnce,fSetup);
	std::lock_guard<std::mutex> oLockGuard(gMutex);
	return fAllocateLocked(inSize);
}


// -----------
/*!
	\fn

	Doc.
*/

void fMemoryRelease(void* inPointer) {

	if (!inPointer) return;
	std::lock_guard<std::mutex> oLockGuard(gMutex);
	fReleaseLocked(inPointer);
}


// -----------
/*!
	\fn

	Doc.
*/

AMemoryStats fMemoryStats(void) {

	std::lock_guard<std::mutex> oLockGuard(gMutex);
	return { gLockedBytes, gUnlockedBytes, gDumpableBytes };
}


// -----------
// SQLite memory allocator interface

extern "C" {

// -----------
/*!
	\fn

	Doc.
*/

static void* fSqliteMalloc(int inSize) {

	return inSize > 0 ? fMemoryAllocate(std::size_t(inSize)) : nullptr;
}


// -----------
/*!
	\fn

	Doc.
*/

static void fSqliteFree(void* inPointer) {

	fMemoryRelease(inPointer);
}


// -----------
/*!
	\fn

	Doc.
*/

static int fSqliteSize(void* inPointer) {

	return inPointer ? int(fUsableSize(inPointer)) : 0;
}


// -----------
/*!
	\fn

	Doc.
*/

static void* fSqliteRealloc(void* inPointer, int inSize) {

	if (!inPointer) return fSqliteMalloc(inSize);
	if (inSize <= 0) {
		fMemoryRelease(inPointer);
		return nullptr;
	}

	const std::size_t inOldSize = fUsableSize(inPointer);
	if (std::size_t(inSize) <= inOldSize) return inPointer;

	// blocks are not shrunk
	// Never let a block move and leave its old copy behind: fMemoryAllocate, copy,
	// then zero and release the old block.

	void* oNewPointer = fMemoryAllocate(std::size_t(inSize));
	if (!oNewPointer) return nullptr;
	memcpy(oNewPointer,inPointer,inOldSize);
	fMemoryRelease(inPointer);
	return oNewPointer;
}


// -----------
/*!
	\fn

	Doc.
*/

static int fSqliteRoundup(int inSize) {

	const std::size_t oRounded = fRoundedSize(inSize > 0 ? std::size_t(inSize) : 1);
	return oRounded > std::size_t(INT_MAX) ? inSize : int(oRounded);
}


// -----------
/*!
	\fn

	Doc.
*/

static int fSqliteInit(void*) {

	return SQLITE_OK;
}


// -----------
/*!
	\fn

	Doc.
*/

static void fSqliteShutdown(void*) {

}

} // extern "C"


// -----------
/*!
	\fn

	Makes SQLite use the protected allocator. Returns false, after logging a
	critical message, if SQLite could not be switched over: in that case SQLite
	keeps its default allocator and NOTHING is locked or zeroed, so the caller
	must not open a database.

	Must be called while this SQLite library has no open connection and no
	other thread is inside SQLite. The allocator can only be configured while
	SQLite is uninitialized; if something initialized it before, it is shut
	down first, which is undefined behaviour with a connection open (and drops
	registered auto-extensions). Later calls are cheap and never shut SQLite
	down again, so calling this for every driver instance is safe.
*/

bool fMemoryInstall(void) {

	static std::mutex oInstallMutex;
	static bool oInstalled = false;

	std::lock_guard<std::mutex> oLockGuard(oInstallMutex);
	if (oInstalled) return true;

	std::call_once(gSetupOnce,fSetup);

	static const sqlite3_mem_methods oMemoryMethods = {
		fSqliteMalloc,fSqliteFree,fSqliteRealloc,
		fSqliteSize,fSqliteRoundup,fSqliteInit,
		fSqliteShutdown,nullptr
	};

	const char* oInstallStep = "sqlite3_config(SQLITE_CONFIG_MALLOC)";
	int oReturnCode = sqlite3_config(SQLITE_CONFIG_MALLOC,&oMemoryMethods);
	if (oReturnCode == SQLITE_MISUSE) {
		// SQLite is initialized already. See the precondition above.
		sqlite3_shutdown();
		oReturnCode = sqlite3_config(SQLITE_CONFIG_MALLOC,&oMemoryMethods);
	}
	if (oReturnCode == SQLITE_OK) {
		// Lookaside slots are recycled without going through the allocator,
		// so they would never be zeroed: route everything through the
		// allocator.
		oInstallStep = "sqlite3_config(SQLITE_CONFIG_LOOKASIDE)";
		oReturnCode = sqlite3_config(SQLITE_CONFIG_LOOKASIDE,0,0);
	}
	if (oReturnCode == SQLITE_OK) {
		// Initialize now, so the configuration is in effect and fixed before
		// anything else gets to use SQLite.
		oInstallStep = "sqlite3_initialize()";
		oReturnCode = sqlite3_initialize();
	}
	if (oReturnCode != SQLITE_OK) {
		qCritical(
			"SQLITECIPHER: protected memory NOT installed, %s failed: %s (%d). "
			"SQLite memory is neither locked nor zeroed.",
			oInstallStep,sqlite3_errstr(oReturnCode),oReturnCode
		);
		return false;
	}

	oInstalled = true;
	return true;
}

} // namespace ASqliteCipherSecureMemory
