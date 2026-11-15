// ----------------------------------------------------------
/*!
	\class ASqliteCipherSecureBuffer
	\title
	\brief

	\list
	\li @notice Template file classes/file.h
	\li @copyright Arboreus (http://arboreus.systems)
	\li @author Alexandr Kirilov (http://alexandr.kirilov.me)
	\li @created 15/11/2026 at 13:48:49
	\endlist
*/
// ----------------------------------------------------------

// Class header
#include "asqliteciphersecurebuffer.h"

// Namespace
using namespace ASqliteCipherSecureMemory;


// -----------
/*!
	\fn

	Doc.
*/

ASqliteCipherSecureBuffer::ASqliteCipherSecureBuffer(void) = default;


// -----------
/*!
	\fn

	Doc.
*/

ASqliteCipherSecureBuffer::~ASqliteCipherSecureBuffer(void) {

	mClear();
}


// -----------
/*!
	\fn

	Stores the UTF-8 form of the string, without an intermediate copy on the general heap.
*/

void ASqliteCipherSecureBuffer::mSetUtf8(const QString& inString) {

	mClear();

	QStringEncoder oEncoder(QStringEncoder::Utf8);
	const qsizetype oCapacity = oEncoder.requiredSpace(inString.size());
	pData = static_cast<char *>(ASqliteCipherSecureMemory::fMemoryAllocate(size_t(oCapacity) + 1));
	if (!pData) return;
	char* oEnd = oEncoder.appendToBuffer(pData,inString);
	*oEnd = '\0';
	pSize = int(oEnd - pData);
}


// -----------
/*!
	\fn

	False if nothing is stored, e.g. because protected memory ran out.
*/

bool ASqliteCipherSecureBuffer::mIsValid(void) const {

	return pData != nullptr;
}


// -----------
/*!
	\fn

	Doc.
*/

const char* ASqliteCipherSecureBuffer::mConstData(void) const {

	return pData ? pData : "";
}


// -----------
/*!
	\fn

	Length of the stored data in bytes (UTF-8 code units), without the terminating null.
	This, not QString::mSize(), is the key length to hand to sqlite3_key() / sqlite3_rekey().
*/

int ASqliteCipherSecureBuffer::mSize(void) const {

	return pSize;
}


// -----------
/*!
	\fn

	Doc.
*/

void ASqliteCipherSecureBuffer::mClear(void) {

	ASqliteCipherSecureMemory::fMemoryRelease(pData);
	pData = nullptr;
	pSize = 0;
}
