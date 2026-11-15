// ----------------------------------------------------------
/*!
	\headerfile ASqliteCipherSecureBuffer
	\title
	\brief Template file wizard/classes/cpp/file.h

	\list
	\li @notice Template file classes/file.h
	\li @copyright Arboreus (http://arboreus.systems)
	\li @author Alexandr Kirilov (http://alexandr.kirilov.me)
	\li @created 15/11/2026 at 13:48:49
	\endlist
*/
// ----------------------------------------------------------
#ifndef ASQLITECIPHERSECUREBUFFER_H
#define ASQLITECIPHERSECUREBUFFER_H

// System includes
#include <QObject>

// Application includes
#include <asqlitecipherdatamodels.h>
#include <asqliteciphermemory.h>

// Namesapces

// Constants and definitions

// Class definitions
class ASqliteCipherSecureBuffer {

	Q_DISABLE_COPY(ASqliteCipherSecureBuffer)

	public:

		ASqliteCipherSecureBuffer(void);
		~ASqliteCipherSecureBuffer(void);

		void mSetUtf8(const QString &inString);
		bool mIsValid() const;
		const char* mConstData() const;
		int mSize(void) const;
		void mClear(void);

	private:

		char* pData = nullptr;
		int pSize = 0;
};

#endif // ASQLITECIPHERSECUREBUFFER_H
