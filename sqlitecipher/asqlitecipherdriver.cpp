// ----------------------------------------------------------
/*!
	\class ASQLiteCipherDriver
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
#include <asqlitecipherdriver.h>

// Private include
#include <asqlitecipherprivate.h>

// Constants
Q_DECLARE_OPAQUE_POINTER(sqlite3*)
Q_DECLARE_METATYPE(sqlite3*)
Q_DECLARE_OPAQUE_POINTER(sqlite3_stmt*)
Q_DECLARE_METATYPE(sqlite3_stmt*)

// Definitions
#define CHECK_SQLITE_KEY \
    do { \
		sqlite3_key(d->pAccess,oPasswordUtf8.mConstData(),oPasswordUtf8.mSize()); \
		int oResult = sqlite3_exec(\
			d->pAccess,\
			QStringLiteral("SELECT count(*) FROM sqlite_master LIMIT 1").toUtf8().constData(),\
			nullptr,\
			nullptr,\
			nullptr\
		); \
		if (oResult != SQLITE_OK) return oFailKeyOperation(tr("Invalid password."),oResult); \
    } while (0)

QT_BEGIN_NAMESPACE

// Classes
class SQLiteResultPrivate;


// -----------
// Memory hardening

// -----------
/*!
	\fn

	Zeroes the characters of a string before releasing it. The buffer is only overwritten if this string
	is its sole owner and the buffer is a heap allocation of its own: a shared buffer is still in use by
	somebody else (who then becomes responsible for it), and string literals / fromRawData() strings
	point at memory that is read-only or not ours.

	needsDetach() is exactly the test data() uses to decide whether to copy, so when it is false, data()
	is guaranteed to return the existing buffer and not a fresh copy of it.

	Zeroes string / blob data held by a variant. The variant keeps its type, so it can stay in a result
	cache until it is overwritten. The payload is reached through QVariant::data(), which detaches the
	variant first, so only this variant's own QString / QByteArray object is touched.
*/

static void fSqliteHardeningSecureWipe(QString& inString) {

	if (!inString.isEmpty() && !inString.data_ptr().needsDetach()) {
		ASqliteCipherSecureMemory::fMemoryZeroing(
			inString.data(),
			size_t(inString.size()) * sizeof(QChar)
		);
	}

	inString.clear();
}

static void fSqliteHardeningSecureWipe(QByteArray& inBiteArray) {

	if (!inBiteArray.isEmpty() && !inBiteArray.data_ptr().needsDetach()) {
		ASqliteCipherSecureMemory::fMemoryZeroing(
			inBiteArray.data(),
			size_t(inBiteArray.size())
		);
	}

	inBiteArray.clear();
}

static void fSqliteHardeningSecureWipe(QVariant& inValue) {

	switch (inValue.userType()) {
		case QMetaType::QString:
			fSqliteHardeningSecureWipe(*static_cast<QString*>(inValue.data()));
			break;
		case QMetaType::QByteArray:
			fSqliteHardeningSecureWipe(*static_cast<QByteArray*>(inValue.data()));
			break;
		default:
			break;
    }
}

static void fSqliteHardeningSecureWipe(QList<QVariant> &inValues) {

	for (QVariant& iValue : inValues) fSqliteHardeningSecureWipe(iValue);
}


// -----------
/*!
	\fn

	Moves all of SQLite's memory into protected regions (see securememory_p.h).
	Must run before SQLite is initialized, i.e. before the first connection.
*/

static void fSqliteHardeningInstallSecureMemory(void) {

	static std::once_flag oOnce;
	std::call_once(oOnce, [] {

		if (!ASqliteCipherSecureMemory::fMemoryInstall()) {
			qWarning("ASQLITECIPHER: unable to enable protected memory, SQLite is already initialized.");
		}
    });
}


// -----------
/*!
	\fn

	Says once if the system did not grant the protections that were asked for.
*/

static void fSqliteHardeningReportSecureMemoryState(void) {

	static std::once_flag oOnce;
	std::call_once(oOnce, [] {

		const ASqliteCipherSecureMemory::AMemoryStats oStats = ASqliteCipherSecureMemory::fMemoryStats();
		if (oStats.UnlockedBytes > 0) {
			qWarning(
				"ASQLITECIPHER: the system refused to lock %zu KiB of database memory into RAM "
				"(per-process limit); that memory can be written to swap.",
				oStats.UnlockedBytes / 1024
			);
		}
		if (oStats.DumpableBytes > 0) {
			qWarning(
				"ASQLITECIPHER: %zu KiB of database memory could not be excluded from core dumps.",
				oStats.DumpableBytes / 1024
			);
        }
    });
}


// -----------
// Sqlite handlers

// -----------
/*!
	\fn

	Doc.
*/

static QString fSqliteEscapeIdentifier(const QString& inIdentifier) {

	QString oOutput = inIdentifier;
	if (!inIdentifier.isEmpty() && !inIdentifier.startsWith(QLatin1Char('"')) && !inIdentifier.endsWith(QLatin1Char('"'))) {
		oOutput.replace(QLatin1Char('"'),QLatin1String("\"\""));
		oOutput.prepend(QLatin1Char('"')).append(QLatin1Char('"'));
		oOutput.replace(QLatin1Char('.'),QLatin1String("\".\""));
    }
	return oOutput;
}


// -----------
/*!
	\fn

	Doc.
*/

static int fSqliteGetColumnType(const QString& inTypeName) {

	const QString oTypeName = inTypeName.toLower();

	if (oTypeName == QLatin1String("integer")
		|| oTypeName == QLatin1String("int"))
		return QMetaType::Int;
	if (oTypeName == QLatin1String("double")
		|| oTypeName == QLatin1String("float")
		|| oTypeName == QLatin1String("real")
		|| oTypeName.startsWith(QLatin1String("numeric")))
		return QMetaType::Double;
	if (oTypeName == QLatin1String("blob"))
		return QMetaType::QByteArray;
	if (oTypeName == QLatin1String("boolean")
		|| oTypeName == QLatin1String("bool"))
		return QMetaType::Bool;
	return QMetaType::QString;
}


// -----------
/*!
	\fn

	Doc.
*/

static QSqlError fSqliteMakeError(
	sqlite3* inAccess, const QString& inDescription, QSqlError::ErrorType inType, int inErrorCode
) {

	return QSqlError(
		inDescription,
		QString(reinterpret_cast<const QChar *>(sqlite3_errmsg16(inAccess))),
		inType,
		QString::number(inErrorCode)
	);
}


// -----------
/*!
	\fn

	Doc.
*/

static int fSqliteCipherNameToValue(const QString& inName) {

	const QString oName = inName.toLower();
	if (oName == QStringLiteral("aes128cbc")) {
		return ASqliteCipherSecureMemory::AES_128_CBC;
	} else if (oName == QStringLiteral("aes256cbc")) {
		return ASqliteCipherSecureMemory::AES_256_CBC;
	} else if (oName == QStringLiteral("chacha20")) {
		return ASqliteCipherSecureMemory::CHACHA20;
	} else if (oName == QStringLiteral("sqlcipher")) {
		return ASqliteCipherSecureMemory::SQLCIPHER;
	} else if (oName == QStringLiteral("rc4")) {
		return ASqliteCipherSecureMemory::RC4;
	} else {
		return ASqliteCipherSecureMemory::UNKNOWN_CIPHER;
	}
}


// -----------
/*!
	\fn

	Doc.
*/

static QString fSqliteCipherValueToName(const ASqliteCipherSecureMemory::QtSqliteCipher& inCipher) {

	switch (inCipher) {
		case ASqliteCipherSecureMemory::AES_128_CBC:
			return QStringLiteral("AES_128_CBC");
		case ASqliteCipherSecureMemory::AES_256_CBC:
			return QStringLiteral("AES_256_CBC");
		case ASqliteCipherSecureMemory::CHACHA20:
			return QStringLiteral("CHACHA20");
		case ASqliteCipherSecureMemory::SQLCIPHER:
			return QStringLiteral("SQLCIPHER");
		case ASqliteCipherSecureMemory::RC4:
			return QStringLiteral("RC4");
		default:
			return QStringLiteral("UNKNOWN");
	}
}


// -----------
/*!
	\fn

	Doc.
*/

static QSqlIndex fSqliteGetTableInfo(QSqlQuery& inQuery, const QString& inTableName, bool inOnlyPIndex = false) {

	QString oSchema;
	QString oTable(inTableName);
	const qsizetype oIndexOfSeparator = inTableName.indexOf(QLatin1Char('.'));
	if (oIndexOfSeparator > -1) {
		oSchema = inTableName.left(oIndexOfSeparator).append(QLatin1Char('.'));
		oTable = inTableName.mid(oIndexOfSeparator + 1);
	}
	inQuery.exec(QLatin1String("PRAGMA ") + oSchema + QLatin1String("table_info (") + fSqliteEscapeIdentifier(oTable) + QLatin1Char(')'));

	QSqlIndex oSQLIndex;
	while (inQuery.next()) {

		bool iIsPrimaryKey = inQuery.value(5).toInt();
		if (inOnlyPIndex && !iIsPrimaryKey) continue;
		QString iTypeName = inQuery.value(2).toString().toLower();
		QString iDefaultValue = inQuery.value(4).toString();
		if (!iDefaultValue.isEmpty() && iDefaultValue.at(0) == QLatin1Char('\'')) {
			const qsizetype oEnd = iDefaultValue.lastIndexOf(QLatin1Char('\''));
			if (oEnd > 0) iDefaultValue = iDefaultValue.mid(1, oEnd - 1);
		}

		QSqlField iSQLField(inQuery.value(1).toString(),QMetaType(fSqliteGetColumnType(iTypeName)),inTableName);
		if (iIsPrimaryKey && (iTypeName == QLatin1String("integer"))) iSQLField.setAutoValue(true);
		iSQLField.setRequired(inQuery.value(3).toInt() != 0);
		iSQLField.setDefaultValue(iDefaultValue);
		oSQLIndex.append(iSQLField);
	}

	return oSQLIndex;
}


// -----------
/*!
	\fn

	Doc.
*/

static void fSqliteHandleCallback(
	void* inObject, int inOperation, char const* inDBName, char const* inTableName, sqlite3_int64 inRowID
) {

	Q_UNUSED(inOperation);
	Q_UNUSED(inDBName);

	SQLiteCipherDriver* oDriver = static_cast<SQLiteCipherDriver*>(inObject);
	if (oDriver) {
		QMetaObject::invokeMethod(
			oDriver,
			"handleNotification",
			Qt::QueuedConnection,
			Q_ARG(QString, QString::fromUtf8(inTableName)),
			Q_ARG(qint64, inRowID)
		);
	}
}


#if QT_CONFIG(regularexpression)

// -----------
/*!
	\fn

	Doc.
*/

static void fSqliteRegexp(sqlite3_context* inContext, int inCounter, sqlite3_value** inArguments) {

	if (Q_UNLIKELY(inCounter != 2)) {
		sqlite3_result_int(inContext, 0);
		return;
	}

	const QString oPattern = QString::fromUtf8(reinterpret_cast<const char*>(sqlite3_value_text(inArguments[0])));
	QString oSubject = QString::fromUtf8(reinterpret_cast<const char*>(sqlite3_value_text(inArguments[1])));
	auto oCache = static_cast<QCache<QString, QRegularExpression>*>(sqlite3_user_data(inContext));
	auto oRegexp = oCache->object(oPattern);

	const bool oWasCached = oRegexp;
	if (!oWasCached) oRegexp = new QRegularExpression(oPattern,QRegularExpression::DontCaptureOption);

	const bool oFound = oSubject.contains(*oRegexp);
	fSqliteHardeningSecureWipe(oSubject);

	if (!oWasCached) oCache->insert(oPattern, oRegexp);

	sqlite3_result_int(inContext,int(oFound));
}


// -----------
/*!
	\fn

	Doc.
*/

static void fSqliteRegexpCleanup(void* inCache) {

	delete static_cast<QCache<QString,QRegularExpression>*>(inCache);
}

#endif



// -----------
// ASqliteCipher driver classes

// Class definition
class SQLiteResult : public QSqlCachedResult {

	Q_DECLARE_PRIVATE(SQLiteResult)
	friend class SQLiteCipherDriver;

	public:

		explicit SQLiteResult(const SQLiteCipherDriver* db);
		~SQLiteResult(void);

		QVariant handle() const override;

	protected:

		bool gotoNext(QSqlCachedResult::ValueCache& row, int idx) override;
		bool reset(const QString &query) override;
		bool prepare(const QString &query) override;
		bool execBatch(bool arrayBind) override;
		bool exec() override;
		int size() override;
		int numRowsAffected() override;
		QVariant lastInsertId() const override;
		QSqlRecord record() const override;
		void detachFromResultSet() override;
		void virtual_hook(int id, void *data) override;
		bool fetchNext() override;
};

// Class definition
class SQLiteCipherDriverPrivate : public QSqlDriverPrivate {

	Q_DECLARE_PUBLIC(SQLiteCipherDriver)

	public:

		sqlite3* pAccess;
		QList <SQLiteResult*> pResults;
		QStringList pNotificationID;

		inline SQLiteCipherDriverPrivate() : QSqlDriverPrivate(), pAccess(nullptr) {}
};

// Class definition
class SQLiteResultPrivate : public QSqlCachedResultPrivate {

	Q_DECLARE_PUBLIC(SQLiteResult)

	public:

		sqlite3_stmt* pStatement;
		bool pSkippedStatus;
		bool pSkipRow;
		QSqlRecord pSqlRecord;
		QList<QVariant> pFirstRow;

		Q_DECLARE_SQLDRIVER_PRIVATE(SQLiteCipherDriver)
		SQLiteResultPrivate(SQLiteResult* q, const SQLiteCipherDriver* drv);
		void cleanup(void);
		bool fetchNext(QSqlCachedResult::ValueCache& values, int idx, bool initialFetch);
		void initColumns(bool emptyResultset);
		void finalize(void);
};


// -----------
// ASqliteCipher driver methods

// -----------
/*!
	\fn

	Doc.
*/

SQLiteResultPrivate::SQLiteResultPrivate(SQLiteResult* q, const SQLiteCipherDriver* drv) : QSqlCachedResultPrivate(q, drv) {

	pStatement = nullptr,
	pSkippedStatus = false,
	pSkipRow = false;
}


// -----------
/*!
	\fn

	Doc.
*/

void SQLiteResultPrivate::cleanup(void) {

	Q_Q(SQLiteResult);
    finalize();
	pSqlRecord.clear();
	pSkippedStatus = false;
	pSkipRow = false;
    q->setAt(QSql::BeforeFirstRow);
    q->setActive(false);
	fSqliteHardeningSecureWipe(pFirstRow);
	fSqliteHardeningSecureWipe(q->cache());
    q->cleanup();
}


// -----------
/*!
	\fn

	Doc.
*/

void SQLiteResultPrivate::finalize(void) {

	if (!pStatement) return;

	sqlite3_finalize(pStatement);
	pStatement = nullptr;
}


// -----------
/*!
	\fn

	Doc.
*/

void SQLiteResultPrivate::initColumns(bool inEmptyResultSet) {

	Q_Q(SQLiteResult);

	int oNumberOfColumns = sqlite3_column_count(pStatement);
	if (oNumberOfColumns <= 0) return;
	q->init(oNumberOfColumns);

	for (int i = 0; i < oNumberOfColumns; ++i) {

		QString iColumnName = QString(reinterpret_cast<const QChar*>(sqlite3_column_name16(pStatement, i))).remove(QLatin1Char('"'));
		const QString iTableName = QString(reinterpret_cast<const QChar*>(sqlite3_column_table_name16(pStatement, i))).remove(QLatin1Char('"'));
		QString iTypeName = QString(reinterpret_cast<const QChar*>(sqlite3_column_decltype16(pStatement, i)));

		int iStorageType = inEmptyResultSet ? -1 : sqlite3_column_type(pStatement,i);
		int iFieldType;

		if (!iTypeName.isEmpty()) {
			iFieldType = fSqliteGetColumnType(iTypeName);
        } else {
			switch (iStorageType) {
				case SQLITE_INTEGER: iFieldType = QMetaType::Int; break;
				case SQLITE_FLOAT: iFieldType = QMetaType::Double; break;
				case SQLITE_BLOB: iFieldType = QMetaType::QByteArray; break;
				case SQLITE_TEXT: iFieldType = QMetaType::QString; break;
				case SQLITE_NULL:
				default: iFieldType = QMetaType::UnknownType; break;
            }
        }

		QSqlField iSQLField(iColumnName,QMetaType(iFieldType),iTableName);
		pSqlRecord.append(iSQLField);
    }
}


// -----------
/*!
	\fn

	Doc.
*/

bool SQLiteResultPrivate::fetchNext(QSqlCachedResult::ValueCache& inValues, int inIndex, bool inInitialFetch) {

	Q_Q(SQLiteResult);

	int oResult;
	int i;

	if (pSkipRow) {
		Q_ASSERT(!inInitialFetch);
		pSkipRow = false;
		for (int i = 0; i < pFirstRow.size(); i++) {
			fSqliteHardeningSecureWipe(inValues[i]);
			inValues[i] = std::move(pFirstRow[i]);
		}
		return pSkippedStatus;
	}
	pSkipRow = inInitialFetch;

	if(inInitialFetch) {
		fSqliteHardeningSecureWipe(pFirstRow);
		pFirstRow.clear();
		pFirstRow.resize(sqlite3_column_count(pStatement));
	}

	if (!pStatement) {
		q->setLastError(
			QSqlError(QCoreApplication::translate("SQLiteResult","Unable to fetch row"),
			QCoreApplication::translate("SQLiteResult","No query"),QSqlError::ConnectionError)
		);
		q->setAt(QSql::AfterLastRow);
		return false;
	}
	oResult = sqlite3_step(pStatement);

	switch(oResult) {
		case SQLITE_ROW:
			if (pSqlRecord.isEmpty()) initColumns(false);
			if (inIndex < 0 && !inInitialFetch) return true;
			for (i = 0; i < pSqlRecord.count(); ++i) {
				fSqliteHardeningSecureWipe(inValues[i + inIndex]);
				switch (sqlite3_column_type(pStatement,i)) {
					case SQLITE_BLOB:
						inValues[i + inIndex] = QByteArray(static_cast<const char*>(
							sqlite3_column_blob(pStatement,i)),
							sqlite3_column_bytes(pStatement,i)
						);
						break;
					case SQLITE_INTEGER:
						inValues[i + inIndex] = sqlite3_column_int64(pStatement,i);
						break;
					case SQLITE_FLOAT:
						switch(q->numericalPrecisionPolicy()) {
							case QSql::LowPrecisionInt32:
								inValues[i + inIndex] = sqlite3_column_int(pStatement,i);
								break;
							case QSql::LowPrecisionInt64:
								inValues[i + inIndex] = sqlite3_column_int64(pStatement,i);
								break;
							case QSql::LowPrecisionDouble:
							case QSql::HighPrecision:
							default:
								inValues[i + inIndex] = sqlite3_column_double(pStatement,i);
								break;
						};
						break;
					case SQLITE_NULL:
						inValues[i + inIndex] = QVariant(QMetaType::fromType<QString>());
						break;
					default:
						inValues[i + inIndex] = QString(reinterpret_cast<const QChar*>(
							sqlite3_column_text16(pStatement, i)),
							sqlite3_column_bytes16(pStatement, i) / sizeof(QChar)
						);
						break;
				}
			}
			return true;
		case SQLITE_DONE:
			if (pSqlRecord.isEmpty()) initColumns(true);
			q->setAt(QSql::AfterLastRow);
			sqlite3_reset(pStatement);
			return false;
		case SQLITE_CONSTRAINT:
		case SQLITE_ERROR:
			oResult = sqlite3_reset(pStatement);
			q->setLastError(
				fSqliteMakeError(
					drv_d_func()->pAccess,
					QCoreApplication::translate("SQLiteResult","Unable to fetch row"),
					QSqlError::ConnectionError,
					oResult
				)
			);
			q->setAt(QSql::AfterLastRow);
			return false;
		case SQLITE_MISUSE:
		case SQLITE_BUSY:
		default:
			q->setLastError(
				fSqliteMakeError(
					drv_d_func()->pAccess,
					QCoreApplication::translate("SQLiteResult","Unable to fetch row"),
					QSqlError::ConnectionError, oResult
				)
			);
			sqlite3_reset(pStatement);
			q->setAt(QSql::AfterLastRow);
			return false;
	}
	return false;
}


// -----------
/*!
	\fn

	Doc.
*/

SQLiteResult::SQLiteResult(const SQLiteCipherDriver* inDB) : QSqlCachedResult(*new SQLiteResultPrivate(this,inDB)) {

	Q_D(SQLiteResult);
	const_cast<SQLiteCipherDriverPrivate*>(d->drv_d_func())->pResults.append(this);
}


// -----------
/*!
	\fn

	Doc.
*/

SQLiteResult::~SQLiteResult(void) {

	Q_D(SQLiteResult);
	if (d->drv_d_func()) const_cast<SQLiteCipherDriverPrivate*>(d->drv_d_func())->pResults.removeOne(this);
	d->cleanup();
}


// -----------
/*!
	\fn

	Doc.
*/

void SQLiteResult::virtual_hook(int inID, void* inData) {

	QSqlCachedResult::virtual_hook(inID,inData);
}


// -----------
/*!
	\fn

	Doc.
*/

bool SQLiteResult::reset(const QString &inQuery) {

	if (!prepare(inQuery)) return false;
	return exec();
}


// -----------
/*!
	\fn

	Doc.
*/

bool SQLiteResult::prepare(const QString& inQuery) {

	Q_D(SQLiteResult);

	if (!driver() || !driver()->isOpen() || driver()->isOpenError()) return false;
	d->cleanup();
	setSelect(false);

	const void* oPointerZTail = nullptr;
	const auto oSize = int((inQuery.size() + 1) * sizeof(QChar));

	int oResult = sqlite3_prepare16_v2(d->drv_d_func()->pAccess,inQuery.constData(),oSize,&d->pStatement,&oPointerZTail);
	if (oResult != SQLITE_OK) {
		setLastError(
			fSqliteMakeError(
				d->drv_d_func()->pAccess,
				QCoreApplication::translate("SQLiteResult","Unable to execute statement"),
				QSqlError::StatementError,
				oResult
			)
		);
		d->finalize();
		return false;
	} else if (oPointerZTail && !QString(reinterpret_cast<const QChar*>(oPointerZTail)).trimmed().isEmpty()) {
		setLastError(
			fSqliteMakeError(
				d->drv_d_func()->pAccess,
				QCoreApplication::translate("SQLiteResult","Unable to execute multiple statements at a time"),
				QSqlError::StatementError,
				SQLITE_MISUSE
			)
		);
		d->finalize();
		return false;
	}
	return true;
}


// -----------
/*!
	\fn

	Doc.
*/

bool SQLiteResult::execBatch(bool inArrayBind) {

	Q_UNUSED(inArrayBind)

	Q_D(QSqlResult);

	QScopedValueRollback<QList<QVariant>> oValuesScope(d->values);
	QList<QVariant> oValues = d->values;
	if (oValues.size() == 0) return false;

	for (int i = 0; i < oValues.at(0).toList().size(); ++i) {

		d->values.clear();
		QScopedValueRollback<QHash<QString,QList<int>>> iIndexesScope(d->indexes);
		auto iIt = d->indexes.constBegin();
		while (iIt != d->indexes.constEnd()) {
			bindValue(
				iIt.key(),
				oValues.at(iIt.value().first()).toList().at(i),
				QSql::In
			);
			++iIt;
		}
		if (!exec()) return false;
	}

	return true;
}


// -----------
/*!
	\fn

	Doc.
*/

bool SQLiteResult::exec(void) {

	Q_D(SQLiteResult);

	QList<QVariant> oValues = boundValues();

	d->pSkippedStatus = false;
	d->pSkipRow = false;
	d->pSqlRecord.clear();

	fSqliteHardeningSecureWipe(d->pFirstRow);
	fSqliteHardeningSecureWipe(cache());
	clearValues();
	setLastError(QSqlError());

	int oResult = sqlite3_reset(d->pStatement);
	if (oResult != SQLITE_OK) {
		setLastError(
			fSqliteMakeError(
				d->drv_d_func()->pAccess,
				QCoreApplication::translate("SQLiteResult","Unable to reset statement"),
				QSqlError::StatementError,
				oResult
			)
		);
		d->finalize();
		return false;
	}

	int oParametersCount = sqlite3_bind_parameter_count(d->pStatement);
	bool oParametersCountIsValid = oParametersCount == oValues.size();
	if (oParametersCount >= 1 && oParametersCount < oValues.size()) {

		const auto oCountIndexes = [](int counter, const QList<int> &indexList) {
			return counter + int(indexList.size());
		};

		const int bindParamCount = std::accumulate(d->indexes.cbegin(),d->indexes.cend(),0,oCountIndexes);
		oParametersCountIsValid = bindParamCount == oValues.size();
		QList<QVariant> oPrunedValues;
		QList<int> oHandledIndexes;

		for (int i = 0, iCurrentIndex = 0; i < oValues.size(); ++i) {

			if (oHandledIndexes.contains(i)) continue;
			const char* parameterName = sqlite3_bind_parameter_name(d->pStatement,iCurrentIndex + 1);
			if (!parameterName) {
				oParametersCountIsValid = false;
				continue;
			}
			const auto placeHolder = QString::fromUtf8(parameterName);
			const auto &indexes = d->indexes.value(placeHolder);
			oHandledIndexes << indexes;
			oPrunedValues << oValues.at(indexes.first());
			++iCurrentIndex;
		}
		oValues = oPrunedValues;
	}

	if (oParametersCountIsValid) {

		for (int i = 0; i < oParametersCount; ++i) {

			const QVariant& iValue = oValues.at(i);

			if (QSqlResultPrivate::isVariantNull(iValue)) {
				oResult = sqlite3_bind_null(d->pStatement, i + 1);
			} else {
				switch (iValue.userType()) {
					case QMetaType::QByteArray:
						{
							const QByteArray* iByteArray = static_cast<const QByteArray*>(iValue.constData());
							oResult = sqlite3_bind_blob(
								d->pStatement,i + 1,
								iByteArray->constData(),
								int(iByteArray->size()),
								SQLITE_STATIC
							);
							break;
						}
					case QMetaType::Int:
					case QMetaType::Bool:
						oResult = sqlite3_bind_int(d->pStatement,i + 1,iValue.toInt());
						break;
					case QMetaType::Double:
						oResult = sqlite3_bind_double(d->pStatement,i + 1,iValue.toDouble());
						break;
					case QMetaType::UInt:
					case QMetaType::LongLong:
						oResult = sqlite3_bind_int64(d->pStatement,i + 1,iValue.toLongLong());
						break;
					case QMetaType::QDateTime:
						{
							const QDateTime iDateTime = iValue.toDateTime();
							QString iString = iDateTime.toString(Qt::ISODateWithMs);
							oResult = sqlite3_bind_text16(
								d->pStatement,
								i + 1,
								iString.utf16(),
								int(iString.size() * sizeof(QChar)),
								SQLITE_TRANSIENT
							);
							fSqliteHardeningSecureWipe(iString);
							break;
						}
					case QMetaType::QTime:
						{
							const QTime iTime = iValue.toTime();
							QString iString = iTime.toString(QStringLiteral("hh:mm:ss.zzz"));
							oResult = sqlite3_bind_text16(
								d->pStatement,
								i + 1,
								iString.utf16(),
								int(iString.size() * sizeof(QChar)),
								SQLITE_TRANSIENT
							);
							fSqliteHardeningSecureWipe(iString);
							break;
						}
					case QMetaType::QString:
						{
							const QString* iString = static_cast<const QString*>(iValue.constData());
							oResult = sqlite3_bind_text16(
								d->pStatement,
								i + 1,
								iString->utf16(),
								int(iString->size() * sizeof(QChar)),
								SQLITE_STATIC
							);
							break;
						}
					default:
						{
							QString iString = iValue.toString();
							oResult = sqlite3_bind_text16(
								d->pStatement,
								i + 1,
								iString.utf16(),
								int(iString.size() * sizeof(QChar)),
								SQLITE_TRANSIENT
							);
							fSqliteHardeningSecureWipe(iString);
							break;
						}
				}
			}
			if (oResult != SQLITE_OK) {
				setLastError(
					fSqliteMakeError(
						d->drv_d_func()->pAccess,
						QCoreApplication::translate("SQLiteResult","Unable to bind parameters"),
						QSqlError::StatementError,
						oResult
					)
				);
				d->finalize();
				return false;
			}
		}

	} else {
		setLastError(
			QSqlError(
				QCoreApplication::translate("SQLiteResult","Parameter count mismatch"),
				QString(),
				QSqlError::StatementError
			)
		);
		return false;
	}

	d->pSkippedStatus = d->fetchNext(d->pFirstRow,0,true);

	if (lastError().isValid()) {
		setSelect(false);
		setActive(false);
		return false;
	}

	setSelect(!d->pSqlRecord.isEmpty());
	setActive(true);

	return true;
}


// -----------
/*!
	\fn

	Doc.
*/

bool SQLiteResult::gotoNext(QSqlCachedResult::ValueCache& inRow, int inIndex) {

	Q_D(SQLiteResult);

	return d->fetchNext(inRow, inIndex, false);
}


// -----------
/*!
	\fn

	Doc.
*/

bool SQLiteResult::fetchNext(void) {

	if (isForwardOnly()) fSqliteHardeningSecureWipe(cache());
	return QSqlCachedResult::fetchNext();
}


// -----------
/*!
	\fn

	Doc.
*/

int SQLiteResult::size(void) {

	return -1;
}


// -----------
/*!
	\fn

	Doc.
*/

int SQLiteResult::numRowsAffected(void) {

	Q_D(const SQLiteResult);

	return sqlite3_changes(d->drv_d_func()->pAccess);
}


// -----------
/*!
	\fn

	Doc.
*/

QVariant SQLiteResult::lastInsertId() const {

	Q_D(const SQLiteResult);

	if (isActive()) {
		qint64 oID = sqlite3_last_insert_rowid(d->drv_d_func()->pAccess);
		if (oID) return oID;
	}

	return QVariant();
}


// -----------
/*!
	\fn

	Doc.
*/

QSqlRecord SQLiteResult::record() const {

	Q_D(const SQLiteResult);

	if (!isActive() || !isSelect()) return QSqlRecord();
	return d->pSqlRecord;
}


// -----------
/*!
	\fn

	Doc.
*/

void SQLiteResult::detachFromResultSet(void) {

	Q_D(SQLiteResult);

	if (d->pStatement) sqlite3_reset(d->pStatement);
}


// -----------
/*!
	\fn

	Doc.
*/

QVariant SQLiteResult::handle() const {

	Q_D(const SQLiteResult);

	return QVariant::fromValue(d->pStatement);
}


// -----------
/*!
	\fn

	Doc.
*/

SQLiteCipherDriver::SQLiteCipherDriver(QObject* parent) : QSqlDriver(*new SQLiteCipherDriverPrivate, parent) {

	fSqliteHardeningInstallSecureMemory();
}


// -----------
/*!
	\fn

	Doc.
*/

SQLiteCipherDriver::SQLiteCipherDriver(sqlite3* connection, QObject* parent) : QSqlDriver(*new SQLiteCipherDriverPrivate,parent) {

	Q_D(SQLiteCipherDriver);
	d->pAccess = connection;
	setOpen(true);
	setOpenError(false);
}


// -----------
/*!
	\fn

	Doc.
*/

SQLiteCipherDriver::~SQLiteCipherDriver(void) {

	SQLiteCipherDriver::close();
}


// -----------
/*!
	\fn

	Doc.
*/

bool SQLiteCipherDriver::hasFeature(DriverFeature inFeature) const {

	switch (inFeature) {
		case BLOB:
		case Transactions:
		case Unicode:
		case LastInsertId:
		case PreparedQueries:
		case PositionalPlaceholders:
		case SimpleLocking:
		case FinishQuery:
		case LowPrecisionNumbers:
		case EventNotifications:
			return true;
		case QuerySize:
		case BatchOperations:
		case MultipleResultSets:
		case CancelQuery:
			return false;
		case NamedPlaceholders:
			return true;
	}
	return false;
}



// -----------
/*!
	\fn

	Doc.
*/

bool SQLiteCipherDriver::open(
	const QString& inDB,
	const QString&,
	const QString& inPassword,
	const QString&,
	int,
	const QString& inOptions
) {

	Q_D(SQLiteCipherDriver);

	if (isOpen()) close();

	ASqliteCipherSecureBuffer oPasswordUtf8;
	oPasswordUtf8.mSetUtf8(inPassword);

	ASqliteCipherSecureBuffer oDBUtf8;
	oDBUtf8.mSetUtf8(inDB);

	QString oNewPassword = QString();
	ASqliteCipherSecureBuffer oNewPasswordUtf8;
	const auto oWipeSecrets = qScopeGuard([&] {
		oPasswordUtf8.mClear();
		oDBUtf8.mClear();
		fSqliteHardeningSecureWipe(oNewPassword);
		oNewPasswordUtf8.mClear();
	});

	if (!oPasswordUtf8.mIsValid() || !oDBUtf8.mIsValid()) {
		setLastError(
			QSqlError(
				tr("Error opening database"),
				tr("Unable to allocate protected memory"),
				QSqlError::ConnectionError
			)
		);
		setOpenError(true);
		return false;
	}

	int oTimeOut = 5000;
	int oKeyOption = ASqliteCipherSecureMemory::OPEN_WITH_KEY;
	bool oSharedCache = false;
	bool oOpenReadOnlyOption = false;
	bool oOpenUriOption = false;
	int oCipher = -1;

	// AES128CBC
	bool oAES128CBCLegacy = false;
	int oAES128CBCLegacyPageSize = 0;

	// AES256CBC
	bool oAES256CBCLegacy = false;
	int oAES256CBCKdfIteration = 4001;
	int oAES256CBCLegacyPageSize = 0;

	// CHACHA20
	bool oChaCha20Legacy = false;
	int oChaCha20KdfIteration = 64007;
	int oChaCha20LegacyPageSize = 4096;

	// SQLCIPHER
	int oSqlcipherLegacy = 0;
	int oSqlcipherKdfIter = 256000;
	int oSqlcipherFastKdfIter = 2;
	bool oSqlcipherHmacUse = true;
	int oSqlcipherHmacPgno = 1;
	int oSqlcipherHmacSaltMask = 0x3a;
	int oSqlcipherLegacyPageSize = 4096;
	int oSqlcipherKdfAlgorithm = 2;
	int oSqlcipherHmacAlgorithm = 2;
	int oSqlcipherPlainTextHeaderSize = 0;

	// RC4
	int oRC4LegacyPageSize = 0;

#if QT_CONFIG(regularexpression)
	static const QLatin1String oRegexpConnectOption = QLatin1String("QSQLITE_ENABLE_REGEXP");
	bool oDefineRegexp = false;
	int oRegexpCacheSize = 25;
#endif

	const QList<QStringView> oOptions = QStringView(inOptions).split(QLatin1Char(';'));
	for (QStringView iOption : oOptions) {

		iOption = iOption.trimmed();

		if (iOption.startsWith(QLatin1String("QSQLITE_BUSY_TIMEOUT"))) {
			iOption = iOption.mid(20).trimmed();
			if (iOption.startsWith(QLatin1Char('='))) {
				bool iOK;
				const int iValue = iOption.mid(1).trimmed().toInt(&iOK);
				if (iOK) oTimeOut = iValue;
			}
		}

		if (iOption.startsWith(QLatin1String("QSQLITE_UPDATE_KEY"))) {
			iOption = iOption.mid(18).trimmed();
			if (iOption.startsWith(QLatin1Char('='))) oNewPassword = iOption.mid(1).trimmed().toString();
			oKeyOption = ASqliteCipherSecureMemory::UPDATE_KEY;
		}

		if (iOption.startsWith(QLatin1String("QSQLITE_USE_CIPHER"))) {
			iOption = iOption.mid(18).trimmed();
			if (iOption.startsWith(QLatin1Char('='))) oCipher = fSqliteCipherNameToValue(iOption.mid(1).trimmed().toString());
		}

		if (iOption.startsWith(QLatin1String("AES128CBC_LEGACY"))) {
			iOption = iOption.mid(16).trimmed();
			if (iOption.startsWith(QLatin1Char('='))) {
				bool iOK;
				const int iValue = iOption.mid(1).trimmed().toInt(&iOK);
				if (iOK) oAES128CBCLegacy = iValue;
			}
		}

		if (iOption.startsWith(QLatin1String("AES128CBC_LEGACY_PAGE_SIZE"))) {
			iOption = iOption.mid(26).trimmed();
			if (iOption.startsWith(QLatin1Char('='))) {
				bool iOK;
				const int iValue = iOption.mid(1).trimmed().toInt(&iOK);
				if (iOK) {
					oAES128CBCLegacyPageSize = iValue;
					if (oAES128CBCLegacyPageSize < 0) {
						oAES128CBCLegacyPageSize = 0;
					} else if (oAES128CBCLegacyPageSize > 65536) {
						oAES128CBCLegacyPageSize = 65536;
					}
				}
			}
		}

		if (iOption.startsWith(QLatin1String("AES256CBC_LEGACY"))) {
			iOption = iOption.mid(16).trimmed();
			if (iOption.startsWith(QLatin1Char('='))) {
				bool iOK;
				const int iValue = iOption.mid(1).trimmed().toInt(&iOK);
				if (iOK) oAES256CBCLegacy = iValue;
			}
		}

		if (iOption.startsWith(QLatin1String("AES256CBC_LEGACY_PAGE_SIZE"))) {
			iOption = iOption.mid(26).trimmed();
			if (iOption.startsWith(QLatin1Char('='))) {
				bool iOK;
				const int iValue = iOption.mid(1).trimmed().toInt(&iOK);
				if (iOK) {
					oAES256CBCLegacyPageSize = iValue;
					if (oAES256CBCLegacyPageSize < 0) {
						oAES256CBCLegacyPageSize = 0;
					} else if (oAES256CBCLegacyPageSize > 65536) {
						oAES256CBCLegacyPageSize = 65536;
					}
				}
			}
		}

		if (iOption.startsWith(QLatin1String("AES256CBC_KDF_ITER"))) {
			iOption = iOption.mid(18).trimmed();
			if (iOption.startsWith(QLatin1Char('='))) {
				bool iOK;
				const int iValue = iOption.mid(1).trimmed().toInt(&iOK);
				if (iOK) {
					oAES256CBCKdfIteration = iValue;
					if (oAES256CBCKdfIteration < 1) oAES256CBCKdfIteration = 1;
				}
			}
		}

		if (iOption.startsWith(QLatin1String("CHACHA20_LEGACY"))) {
			iOption = iOption.mid(15).trimmed();
			if (iOption.startsWith(QLatin1Char('='))) {
				bool iOK;
				const int iValue = iOption.mid(1).trimmed().toInt(&iOK);
				if (iOK) oChaCha20Legacy = iValue;
			}
		}

		if (iOption.startsWith(QLatin1String("CHACHA20_LEGACY_PAGE_SIZE"))) {
			iOption = iOption.mid(25).trimmed();
			if (iOption.startsWith(QLatin1Char('='))) {
				bool iOK;
				const int iValue = iOption.mid(1).trimmed().toInt(&iOK);
				if (iOK) {
					oChaCha20LegacyPageSize = iValue;
					if (oChaCha20LegacyPageSize < 0) {
						oChaCha20LegacyPageSize = 0;
					} else if (oChaCha20LegacyPageSize > 65536) {
						oChaCha20LegacyPageSize = 65536;
					}
				}
			}
		}

		if (iOption.startsWith(QLatin1String("CHACHA20_KDF_ITER"))) {
			iOption = iOption.mid(17).trimmed();
			if (iOption.startsWith(QLatin1Char('='))) {
				bool iOK;
				const int iValue = iOption.mid(1).trimmed().toInt(&iOK);
				if (iOK) {
					oChaCha20KdfIteration = iValue;
					if (oChaCha20KdfIteration < 1) oChaCha20KdfIteration = 1;
				}
			}
		}

		if (iOption.startsWith(QLatin1String("SQLCIPHER_LEGACY"))) {
			iOption = iOption.mid(16).trimmed();
			if (iOption.startsWith(QLatin1Char('='))) {
				bool iOK;
				const int iValue = iOption.mid(1).trimmed().toInt(&iOK);
				if (iOK) {
					oSqlcipherLegacy = iValue;
					if (oSqlcipherLegacy < 0) {
						oSqlcipherLegacy = 0;
					} else if (oSqlcipherLegacy > 4) {
						oSqlcipherLegacy = 4;
					}
				}
			}
		}

		if (iOption.startsWith(QLatin1String("SQLCIPHER_LEGACY_PAGE_SIZE"))) {
			iOption = iOption.mid(26).trimmed();
			if (iOption.startsWith(QLatin1Char('='))) {
				bool iOK;
				const int iValue = iOption.mid(1).trimmed().toInt(&iOK);
				if (iOK) {
					oSqlcipherLegacyPageSize = iValue;
					if (oSqlcipherLegacyPageSize < 0) {
						oSqlcipherLegacyPageSize = 0;
					} else if (oSqlcipherLegacyPageSize > 65536) {
						oSqlcipherLegacyPageSize = 65536;
					}
				}
			}
		}

		if (iOption.startsWith(QLatin1String("SQLCIPHER_KDF_ITER"))) {
			iOption = iOption.mid(18).trimmed();
			if (iOption.startsWith(QLatin1Char('='))) {
				bool iOK;
				const int iValue = iOption.mid(1).trimmed().toInt(&iOK);
				if (iOK) {
					oSqlcipherKdfIter = iValue;
					if (oSqlcipherKdfIter < 1) oSqlcipherKdfIter = 1;
				}
			}
		}

		if (iOption.startsWith(QLatin1String("SQLCIPHER_FAST_KDF_ITER"))) {
			iOption = iOption.mid(23).trimmed();
			if (iOption.startsWith(QLatin1Char('='))) {
				bool iOK;
				const int iValue = iOption.mid(1).trimmed().toInt(&iOK);
				if (iOK) {
					oSqlcipherFastKdfIter = iValue;
					if (oSqlcipherFastKdfIter < 1) oSqlcipherFastKdfIter = 1;
				}
			}
		}

		if (iOption.startsWith(QLatin1String("SQLCIPHER_HMAC_USE"))) {
			iOption = iOption.mid(18).trimmed();
			if (iOption.startsWith(QLatin1Char('='))) {
				bool iOK;
				const int iValue = iOption.mid(1).trimmed().toInt(&iOK);
				if (iOK) oSqlcipherHmacUse = iValue;
			}
		}

		if (iOption.startsWith(QLatin1String("SQLCIPHER_HMAC_PGNO"))) {
			iOption = iOption.mid(19).trimmed();
			if (iOption.startsWith(QLatin1Char('='))) {
				bool iOK;
				const int iValue = iOption.mid(1).trimmed().toInt(&iOK);
				if (iOK) {
					oSqlcipherHmacPgno = iValue;
					if (oSqlcipherHmacPgno < 0) oSqlcipherHmacPgno = 0;
					if (oSqlcipherHmacPgno > 2) oSqlcipherHmacPgno = 2;
				}
			}
		}

		if (iOption.startsWith(QLatin1String("SQLCIPHER_HMAC_SALT_MASK"))) {
			iOption = iOption.mid(24).trimmed();
			if (iOption.startsWith(QLatin1Char('='))) {
				bool iOK;
				const int iValue = iOption.mid(1).trimmed().toInt(&iOK);
				if (iOK) {
					oSqlcipherHmacSaltMask = iValue;
					if (oSqlcipherHmacSaltMask < 0) oSqlcipherHmacSaltMask = 0;
					if (oSqlcipherHmacSaltMask > 255) oSqlcipherHmacSaltMask = 255;
				}
			}
		}

		if (iOption.startsWith(QLatin1String("SQLCIPHER_KDF_ALGORITHM"))) {
			iOption = iOption.mid(23).trimmed();
			if (iOption.startsWith(QLatin1Char('='))) {
				bool iOK;
				const int iValue = iOption.mid(1).trimmed().toInt(&iOK);
				if (iOK) {
					oSqlcipherKdfAlgorithm = iValue;
					if (oSqlcipherKdfAlgorithm < 0) oSqlcipherKdfAlgorithm = 0;
					if (oSqlcipherKdfAlgorithm > 2) oSqlcipherKdfAlgorithm = 2;
				}
			}
		}

		if (iOption.startsWith(QLatin1String("SQLCIPHER_HMAC_ALGORITHM"))) {
			iOption = iOption.mid(24).trimmed();
			if (iOption.startsWith(QLatin1Char('='))) {
				bool iOK;
				const int iValue = iOption.mid(1).trimmed().toInt(&iOK);
				if (iOK) {
					oSqlcipherHmacAlgorithm = iValue;
					if (oSqlcipherHmacAlgorithm < 0) oSqlcipherHmacAlgorithm = 0;
					if (oSqlcipherHmacAlgorithm > 2) oSqlcipherHmacAlgorithm = 2;
				}
			}
		}

		if (iOption.startsWith(QLatin1String("SQLCIPHER_PLAINTEXT_HEADER_SIZE"))) {
			iOption = iOption.mid(31).trimmed();
			if (iOption.startsWith(QLatin1Char('='))) {
				bool iOK;
				const int iValue = iOption.mid(1).trimmed().toInt(&iOK);
				if (iOK) {
					oSqlcipherPlainTextHeaderSize = iValue;
					if (oSqlcipherPlainTextHeaderSize < 0) oSqlcipherPlainTextHeaderSize = 0;
					if (oSqlcipherPlainTextHeaderSize > 100) oSqlcipherPlainTextHeaderSize = 100;
				}
			}
		}

		if (iOption.startsWith(QLatin1String("RC4_LEGACY_PAGE_SIZE"))) {
			iOption = iOption.mid(20).trimmed();
			if (iOption.startsWith(QLatin1Char('='))) {
				bool iOK;
				const int iValue = iOption.mid(1).trimmed().toInt(&iOK);
				if (iOK) {
					oRC4LegacyPageSize = iValue;
					if (oRC4LegacyPageSize < 0) {
						oRC4LegacyPageSize = 0;
					} else if (oRC4LegacyPageSize > 65536) {
						oRC4LegacyPageSize = 65536;
					}
				}
			}
		}

		if (iOption == QLatin1String("QSQLITE_OPEN_READONLY")) {
			oOpenReadOnlyOption = true;
		} else if (iOption == QLatin1String("QSQLITE_OPEN_URI")) {
			oOpenUriOption = true;
		} else if (iOption == QLatin1String("QSQLITE_ENABLE_SHARED_CACHE")) {
			oSharedCache = true;
		} else if (iOption == QLatin1String("QSQLITE_CREATE_KEY")) {
			oKeyOption = ASqliteCipherSecureMemory::CREATE_KEY;
		} else if (iOption == QLatin1String("QSQLITE_REMOVE_KEY")) {
			oKeyOption = ASqliteCipherSecureMemory::REMOVE_KEY;
		}
#if QT_CONFIG(regularexpression)
		else if (iOption.startsWith(oRegexpConnectOption)) {
			iOption = iOption.mid(oRegexpConnectOption.size()).trimmed();
			if (iOption.isEmpty()) {
				oDefineRegexp = true;
			} else if (iOption.startsWith(QLatin1Char('='))) {
				bool iOK = false;
				const int iCacheSize = iOption.mid(1).trimmed().toInt(&iOK);
				if (iOK) {
					oDefineRegexp = true;
					if (iCacheSize > 0)
						oRegexpCacheSize = iCacheSize;
				}
			}
		}
#endif
	}

	int oOpenMode = (oOpenReadOnlyOption ? SQLITE_OPEN_READONLY : (SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE));
	oOpenMode |= (oSharedCache ? SQLITE_OPEN_SHAREDCACHE : SQLITE_OPEN_PRIVATECACHE);
	if (oOpenUriOption) oOpenMode |= SQLITE_OPEN_URI;
	oOpenMode |= SQLITE_OPEN_NOMUTEX;

	const int oOpenResult = sqlite3_open_v2(oDBUtf8.mConstData(),&d->pAccess,oOpenMode,nullptr);
	if (oOpenResult == SQLITE_OK) {

		sqlite3_busy_timeout(d->pAccess, oTimeOut);
		fSqliteHardeningReportSecureMemoryState();
		setOpen(true);
		setOpenError(false);

#if QT_CONFIG(regularexpression)
		if (oDefineRegexp) {
			auto oCache = new QCache<QString,QRegularExpression>(oRegexpCacheSize);
			sqlite3_create_function_v2(
				d->pAccess,"regexp",2,SQLITE_UTF8,oCache,&fSqliteRegexp, nullptr,nullptr,&fSqliteRegexpCleanup
			);
		}
#endif
		if (oCipher > 0) {
			sqlite3mc_config(d->pAccess,"cipher",oCipher);
			switch (oCipher) {
				case ASqliteCipherSecureMemory::AES_128_CBC:
					{
						sqlite3mc_config_cipher(d->pAccess,"aes128cbc","legacy",oAES128CBCLegacy ? 1 : 0);
						sqlite3mc_config_cipher(d->pAccess,"aes128cbc","legacy_page_size",oAES128CBCLegacyPageSize);
						break;
					}
				case ASqliteCipherSecureMemory::AES_256_CBC:
					{
						sqlite3mc_config_cipher(d->pAccess,"aes256cbc","legacy",oAES256CBCLegacy ? 1 : 0);
						sqlite3mc_config_cipher(d->pAccess,"aes256cbc","legacy_page_size",oAES256CBCLegacyPageSize);
						sqlite3mc_config_cipher(d->pAccess,"aes256cbc","kdf_iter",oAES256CBCKdfIteration);
						break;
					}
				case ASqliteCipherSecureMemory::CHACHA20:
					{
						sqlite3mc_config_cipher(d->pAccess,"chacha20","legacy",oChaCha20Legacy ? 1 : 0);
						sqlite3mc_config_cipher(d->pAccess,"chacha20","legacy_page_size",oChaCha20LegacyPageSize);
						sqlite3mc_config_cipher(d->pAccess,"chacha20","kdf_iter",oChaCha20KdfIteration);
						break;
					}
				case ASqliteCipherSecureMemory::SQLCIPHER:
					{
						sqlite3mc_config_cipher(d->pAccess,"sqlcipher","legacy",oSqlcipherLegacy);
						sqlite3mc_config_cipher(d->pAccess,"sqlcipher","legacy_page_size",oSqlcipherLegacyPageSize);
						sqlite3mc_config_cipher(d->pAccess,"sqlcipher","kdf_iter",oSqlcipherKdfIter);
						sqlite3mc_config_cipher(d->pAccess,"sqlcipher","fast_kdf_iter",oSqlcipherFastKdfIter);
						sqlite3mc_config_cipher(d->pAccess,"sqlcipher","hmac_use",oSqlcipherHmacUse ? 1 : 0);
						sqlite3mc_config_cipher(d->pAccess,"sqlcipher","hmac_pgno",oSqlcipherHmacPgno);
						sqlite3mc_config_cipher(d->pAccess,"sqlcipher","hmac_salt_mask",oSqlcipherHmacSaltMask);
						sqlite3mc_config_cipher(d->pAccess,"sqlcipher","kdf_algorithm",oSqlcipherKdfAlgorithm);
						sqlite3mc_config_cipher(d->pAccess,"sqlcipher","hmac_algorithm",oSqlcipherHmacAlgorithm);
						sqlite3mc_config_cipher(d->pAccess,"sqlcipher","plaintext_header_size",oSqlcipherPlainTextHeaderSize);
						break;
					}
				case ASqliteCipherSecureMemory::RC4:
					{
						sqlite3mc_config_cipher(d->pAccess,"rc4","legacy", 1);
						sqlite3mc_config_cipher(d->pAccess,"rc4","legacy_page_size",oRC4LegacyPageSize);
						break;
					}
				default: break;
			}
		}

		// Reports a failed key operation and gives up the connection. The
		// error text is read before the handle is closed, and the handle is
		// cleared so that nothing touches it afterwards.
		const auto oFailKeyOperation = [this,d](const QString &descr,int res) {

			setLastError(fSqliteMakeError(d->pAccess,descr,QSqlError::ConnectionError, res));
			sqlite3_close_v2(d->pAccess);
			d->pAccess = nullptr;
			setOpenError(true);
			setOpen(false);
			return false;
		};

		if (!(inPassword.isNull() || inPassword.isEmpty())) {

			switch (oKeyOption) {
				case ASqliteCipherSecureMemory::OPEN_WITH_KEY:
					{
						CHECK_SQLITE_KEY;
						break;
					}
				case ASqliteCipherSecureMemory::CREATE_KEY:
					{
						int oResult = sqlite3_rekey(d->pAccess, oPasswordUtf8.mConstData(), oPasswordUtf8.mSize());
						if (SQLITE_OK != oResult) return oFailKeyOperation(tr("Cannot create password. Maybe it is encrypted?"),oResult);
						break;
					}
				case ASqliteCipherSecureMemory::UPDATE_KEY:
					{
						CHECK_SQLITE_KEY;
						int oResult;
						if (oNewPassword.isEmpty() || oNewPassword.isNull()) {
							oResult = sqlite3_rekey(d->pAccess,nullptr,0);
						} else {
							oNewPasswordUtf8.mSetUtf8(oNewPassword);
							if (!oNewPasswordUtf8.mIsValid()) return oFailKeyOperation(tr("Cannot change password."),SQLITE_NOMEM);
							oResult = sqlite3_rekey(d->pAccess,oNewPasswordUtf8.mConstData(),oNewPasswordUtf8.mSize());
						}
						if (SQLITE_OK != oResult) return oFailKeyOperation(tr("Cannot change password."),oResult);
						break;
					}
				case ASqliteCipherSecureMemory::REMOVE_KEY:
					{
						CHECK_SQLITE_KEY;
						const int oResult = sqlite3_rekey(d->pAccess, nullptr, 0);
						if (SQLITE_OK != oResult) return oFailKeyOperation(tr("Cannot remove password."),oResult);
						break;
					}
			}
		}

		return true;

	} else {

		setLastError(
			fSqliteMakeError(
				d->pAccess,
				tr("Error opening database"),
				QSqlError::ConnectionError,
				oOpenResult
			)
		);
		setOpenError(true);
		setOpen(false);
		if (d->pAccess) {
			sqlite3_close(d->pAccess);
			d->pAccess = nullptr;
		}

		return false;
	}
}


// -----------
/*!
	\fn

	Doc.
*/

void SQLiteCipherDriver::close(void) {

	Q_D(SQLiteCipherDriver);

	if (isOpen()) {

		for (auto iResult : std::as_const(d->pResults)) iResult->d_func()->finalize();

		if (d->pAccess && (d->pNotificationID.size() > 0)) {
			d->pNotificationID.clear();
			sqlite3_update_hook(d->pAccess,nullptr,nullptr);
		}

		const int oResult = sqlite3_close(d->pAccess);
		if (oResult != SQLITE_OK) {
			setLastError(
				fSqliteMakeError(
					d->pAccess,
					tr("Error closing database."),
					QSqlError::ConnectionError,
					oResult
				)
			);
		}

		d->pAccess = nullptr;
		setOpen(false);
		setOpenError(false);
	}
}


// -----------
/*!
	\fn

	Doc.
*/

QSqlResult* SQLiteCipherDriver::createResult(void) const {

	return new SQLiteResult(this);
}


// -----------
/*!
	\fn

	Doc.
*/

bool SQLiteCipherDriver::beginTransaction(void) {

	if (!isOpen() || isOpenError()) return false;

	QSqlQuery oQuery(createResult());
	if (!oQuery.exec(QLatin1String("BEGIN"))) {
		setLastError(
			QSqlError(
				tr("Unable to begin transaction"),
				oQuery.lastError().databaseText(),
				QSqlError::TransactionError
			)
		);
		return false;
	}

	return true;
}


// -----------
/*!
	\fn

	Doc.
*/

bool SQLiteCipherDriver::commitTransaction(void) {

	if (!isOpen() || isOpenError()) return false;

	QSqlQuery oQuery(createResult());
	if (!oQuery.exec(QLatin1String("COMMIT"))) {
		setLastError(QSqlError(tr("Unable to commit transaction"),oQuery.lastError().databaseText(), QSqlError::TransactionError));
		return false;
	}

	return true;
}


// -----------
/*!
	\fn

	Doc.
*/

bool SQLiteCipherDriver::rollbackTransaction(void) {

	if (!isOpen() || isOpenError()) return false;

	QSqlQuery oQuery(createResult());
	if (!oQuery.exec(QLatin1String("ROLLBACK"))) {
		setLastError(
			QSqlError(
				tr("Unable to rollback transaction"),
				oQuery.lastError().databaseText(),
				QSqlError::TransactionError
			)
		);
		return false;
	}

	return true;
}


// -----------
/*!
	\fn

	Doc.
*/

QStringList SQLiteCipherDriver::tables(QSql::TableType inType) const {

	QStringList oResult;
	if (!isOpen()) return oResult;

	QSqlQuery oQuery(createResult());
	oQuery.setForwardOnly(true);

	QString oSQL = QLatin1String(
		"SELECT name FROM sqlite_master WHERE %1 "
		"UNION ALL SELECT name FROM sqlite_temp_master WHERE %1"
	);
	if ((inType & QSql::Tables) && (inType & QSql::Views)) {
		oSQL = oSQL.arg(QLatin1String("type='table' OR type='view'"));
	} else if (inType & QSql::Tables) {
		oSQL = oSQL.arg(QLatin1String("type='table'"));
	} else if (inType & QSql::Views) {
		oSQL = oSQL.arg(QLatin1String("type='view'"));
	} else {
		oSQL.clear();
	}

	if (!oSQL.isEmpty() && oQuery.exec(oSQL)) while(oQuery.next()) oResult.append(oQuery.value(0).toString());
	if (inType & QSql::SystemTables) oResult.append(QLatin1String("sqlite_master"));

	return oResult;
}


// -----------
/*!
	\fn

	Doc.
*/

QSqlIndex SQLiteCipherDriver::primaryIndex(const QString& inTableName) const {

	if (!isOpen()) return QSqlIndex();

	QString oTable = inTableName;
	if (isIdentifierEscaped(oTable,QSqlDriver::TableName)) {
		oTable = stripDelimiters(oTable,QSqlDriver::TableName);
	}

	QSqlQuery oQuery(createResult());
	oQuery.setForwardOnly(true);

	return fSqliteGetTableInfo(oQuery,oTable,true);
}


// -----------
/*!
	\fn

	Doc.
*/

QSqlRecord SQLiteCipherDriver::record(const QString& inTableName) const {

	if (!isOpen()) return QSqlRecord();

	QString oTable = inTableName;
	if (isIdentifierEscaped(oTable, QSqlDriver::TableName)) {
		oTable = stripDelimiters(oTable, QSqlDriver::TableName);
	}

	QSqlQuery oQuery(createResult());
	oQuery.setForwardOnly(true);

	return fSqliteGetTableInfo(oQuery,oTable);
}


// -----------
/*!
	\fn

	Doc.
*/

QVariant SQLiteCipherDriver::handle(void) const {

	Q_D(const SQLiteCipherDriver);

	return QVariant::fromValue(d->pAccess);
}


// -----------
/*!
	\fn

	Doc.
*/

QString SQLiteCipherDriver::escapeIdentifier(const QString& inIdentifier, IdentifierType inType) const {

	Q_UNUSED(inType);

	return fSqliteEscapeIdentifier(inIdentifier);
}


// -----------
/*!
	\fn

	Doc.
*/

bool SQLiteCipherDriver::subscribeToNotification(const QString& inName) {

	Q_D(SQLiteCipherDriver);
	if (!isOpen()) {
		qWarning("Database not open.");
		return false;
	}

	if (d->pNotificationID.contains(inName)) {
		qWarning("Already subscribing to '%s'.", qPrintable(inName));
		return false;
	}

	d->pNotificationID << inName;
	if (d->pNotificationID.size() == 1) {
		sqlite3_update_hook(d->pAccess,&fSqliteHandleCallback,reinterpret_cast<void*>(this));
	}

	return true;
}


// -----------
/*!
	\fn

	Doc.
*/

bool SQLiteCipherDriver::unsubscribeFromNotification(const QString& inName) {

	Q_D(SQLiteCipherDriver);
	if (!isOpen()) {
		qWarning("Database not open.");
		return false;
	}

	if (!d->pNotificationID.contains(inName)) {
		qWarning("Not subscribed to '%s'.",qPrintable(inName));
		return false;
	}

	d->pNotificationID.removeAll(inName);
	if (d->pNotificationID.isEmpty())
		sqlite3_update_hook(d->pAccess, nullptr, nullptr);

	return true;
}


// -----------
/*!
	\fn

	Doc.
*/

QStringList SQLiteCipherDriver::subscribedToNotifications(void) const {

	Q_D(const SQLiteCipherDriver);

	return d->pNotificationID;
}


// -----------
/*!
	\fn

	Doc.
*/

void SQLiteCipherDriver::handleNotification(const QString& inTableName, qint64 inRowID) {

	Q_D(const SQLiteCipherDriver);

	if (d->pNotificationID.contains(inTableName)) {
		emit notification(inTableName,QSqlDriver::UnknownSource,QVariant(inRowID));
	}
}

QT_END_NAMESPACE
