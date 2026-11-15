// ----------------------------------------------------------
/*!
	\headerfile %{CN}
	\title
	\brief Template file files/cppheader/file.h

	\list
	\li @notice Template file classes/file.h
	\li @copyright Arboreus (http://arboreus.systems)
	\li @author Alexandr Kirilov (http://alexandr.kirilov.me)
	\li @created 15/11/2026 at 15:33:06
	\endlist
*/
// ----------------------------------------------------------

#ifndef ASQLITECIPHERPRIVATE_H
#define ASQLITECIPHERPRIVATE_H

// Precompiled includes

// System includes
#include <cstring>
#include <mutex>
#include <numeric>
#include <utility>
#include <unistd.h>

#if QT_CONFIG(regularexpression)
  #include <qcache.h>
  #include <qregularexpression.h>
#endif

// Qt includes
#include <QList>
#include <QScopeGuard>
#include <QScopedValueRollback>
#include <QStringEncoder>
#include <QStringView>
#include <QVariant>
#include <QCoreApplication>
#include <QDateTime>
#include <QDebug>
#include <QSqlError>
#include <QSqlField>
#include <QSqlIndex>
#include <QSqlQuery>
#include <QtSql/private/qsqlcachedresult_p.h>
#include <QtSql/private/qsqldriver_p.h>

// Application includes
#include "asqliteciphermemory.h"

extern "C" {
#include "sqlite3mc_amalgamation.h"
}

// Constants and defintions

#endif // ASQLITECIPHERPRIVATE_H
