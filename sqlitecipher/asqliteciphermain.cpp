// ----------------------------------------------------------
/*!
	\headerfile ALibUsingJava_v6
	\title
	\brief Template file wizard/classes/cpp/file.h

	\list
	\li @notice Template file classes/file.h
	\li @copyright Arboreus (http://arboreus.systems)
	\li @author Alexandr Kirilov (http://alexandr.kirilov.me)
	\li @created 12/11/2026 at 14:24:48
	\endlist
*/
// ----------------------------------------------------------

#ifndef ASQLITECIPHERMAIN_H
#define ASQLITECIPHERMAIN_H

// Precompiled includes

// System includes
#include <qsqldriverplugin.h>
#include <qstringlist.h>

// Application includes
#include <asqlitecipherdatamodels.h>
#include <asqlitecipherdriver.h>

QT_BEGIN_NAMESPACE

// Global variables
static const char gDriverName[] = "ASQLITECIPHER";

// Class definitions
class ASqliteCipherDriverPlugin : public QSqlDriverPlugin {

	Q_OBJECT
	Q_PLUGIN_METADATA(IID "org.qt-project.Qt.QSqlDriverFactoryInterface" FILE "ASqliteCipherDriverPlugin.json")

	public:

		ASqliteCipherDriverPlugin(void);

		QSqlDriver* create(const QString &) override;
};


// -----------
/*!
	\fn

	Doc.
*/

ASqliteCipherDriverPlugin::ASqliteCipherDriverPlugin(void) : QSqlDriverPlugin() {}


// -----------
/*!
	\fn

	Doc.
*/

QSqlDriver* ASqliteCipherDriverPlugin::create(const QString& inName) {

	if (inName == QLatin1String(gDriverName)) {
		SQLiteCipherDriver* oDriver = new SQLiteCipherDriver();
		return oDriver;
    }

    return nullptr;
}

QT_END_NAMESPACE

#endif // ASQLITECIPHERMAIN_H

#include <asqliteciphermain.moc>
