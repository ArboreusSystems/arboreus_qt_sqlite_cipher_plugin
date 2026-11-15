// ----------------------------------------------------------
/*!
	\headerfile %{CN}
	\title
	\brief Template file files/cppheader/file.h

	\list
	\li @notice Template file classes/file.h
	\li @copyright Arboreus (http://arboreus.systems)
	\li @author Alexandr Kirilov (http://alexandr.kirilov.me)
	\li @created 15/11/2026 at 10:11:02
	\endlist
*/
// ----------------------------------------------------------

#ifndef ASQLITECIPHERDATAMODELS_H
#define ASQLITECIPHERDATAMODELS_H

// Precompiled includes

// System includes
#include <cstddef>
#include <cstdint>

// Application includes

// Constants and defintions
#if !defined(MAP_ANONYMOUS) && defined(MAP_ANON)
#define MAP_ANONYMOUS MAP_ANON
#endif

// Global variables


// Namespace
namespace ASqliteCipherSecureMemory {

constexpr std::size_t gHeaderSize = 16;
constexpr std::size_t gAlignment = 16;
constexpr std::size_t gSlabHeaderSize = 64;
constexpr std::uint32_t gLargeBlock = 0xffffffffu;
constexpr std::uint32_t gMagic = 0x53514c43u;
constexpr std::uint32_t gFreedMagic = 0x66726565u;

constexpr std::size_t gMinSlabSize = std::size_t(64) * 1024;
constexpr std::size_t gMaxSlabSize = std::size_t(256) * 1024;
constexpr std::size_t gBlocksPerSlab = 16;
constexpr std::size_t gMaxSmallUsable = std::size_t(16) * 1024;

// Usable sizes of the classes: 16 byte steps up to 128 bytes, then four steps
// per doubling. At most a quarter of a block is unused that way. The table is
// built at compile time, so its size is a constant the compiler can check.
constexpr int gClassCount = 36;

struct AClassTable {

	std::size_t Sizes[gClassCount];
};
constexpr AClassTable dmMakeClassTable(void) {

	AClassTable table{};
	int count = 0;
	for (std::size_t size = 16; size <= 128; size += 16)
		table.Sizes[count++] = size;
	for (std::size_t base = 128; base < gMaxSmallUsable; base *= 2) {
		for (std::size_t step = 1; step <= 4; ++step)
			table.Sizes[count++] = base + base / 4 * step;
	}
	return table;
}
constexpr AClassTable gClassTable = dmMakeClassTable();

struct AMemoryStats {

	std::size_t LockedBytes;      // protected memory locked into RAM
	std::size_t UnlockedBytes;    // protected memory the system refused to lock
	std::size_t DumpableBytes;    // protected memory that may show up in a core dump
};

struct AFreeBlock {

	AFreeBlock* Next;
};

struct ASlab {

	ASlab* Previous;             // list of the slabs of a class that have room
	ASlab* Next;
	AFreeBlock* FreeList;        // freed blocks of this slab
	std::size_t RegionSize;
	std::uint32_t SizeClass;
	std::uint32_t Capacity;     // blocks this slab can hold
	std::uint32_t Carved;       // blocks cut from the slab so far
	std::uint32_t InUse;        // blocks currently handed out
	std::uint8_t Locked;
	std::uint8_t Dumpable;
	std::uint8_t Listed;        // member of the "has room" list
};

struct AHeader {

	std::uint32_t SizeClass;    // index into the class table, or LargeBlock
	std::uint32_t Magic;        // catches pointers that do not belong to us
	union {
		ASlab* Slab;             // small block: the slab it was cut from
		std::size_t Usable;     // large block: bytes available to the caller
	};
#if SIZE_MAX == UINT32_MAX
	std::uint32_t Padding;      // keep the header at 16 bytes on 32 bit systems
#endif
};

struct ALargeTrailer {

	std::size_t RegionSize;
	std::uint8_t Locked;
	std::uint8_t Dumpable;
};

static_assert(sizeof(AHeader) == gHeaderSize, "unexpected block header size");
static_assert(sizeof(ASlab) <= gSlabHeaderSize, "slab header too big");
static_assert(sizeof(AFreeBlock) <= 16, "free list entry must fit the smallest block");
static_assert(gClassTable.Sizes[gClassCount - 1] == gMaxSmallUsable,"the size class table must end at the biggest small block");

enum QtSqliteCipher {

	UNKNOWN_CIPHER = 0,
	AES_128_CBC,
	AES_256_CBC,
	CHACHA20,
	SQLCIPHER,
	RC4
};

enum KEY_OP {

	OPEN_WITH_KEY = 0,
	CREATE_KEY,
	UPDATE_KEY,
	REMOVE_KEY
};

} // namespace ASqliteCipherSecureMemory

#endif // ASQLITECIPHERDATAMODELS_H
