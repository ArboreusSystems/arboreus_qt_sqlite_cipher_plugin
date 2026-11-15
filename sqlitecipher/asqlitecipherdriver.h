/****************************************************************************
**
** Copyright (C) 2016 The Qt Company Ltd.
** Contact: https://www.qt.io/licensing/
**
** This file is part of the QtSql module of the Qt Toolkit.
**
** $QT_BEGIN_LICENSE:LGPL$
** Commercial License Usage
** Licensees holding valid commercial Qt licenses may use this file in
** accordance with the commercial license agreement provided with the
** Software or, alternatively, in accordance with the terms contained in
** a written agreement between you and The Qt Company. For licensing terms
** and conditions see https://www.qt.io/terms-conditions. For further
** information use the contact form at https://www.qt.io/contact-us.
**
** GNU Lesser General Public License Usage
** Alternatively, this file may be used under the terms of the GNU Lesser
** General Public License version 3 as published by the Free Software
** Foundation and appearing in the file LICENSE.LGPL3 included in the
** packaging of this file. Please review the following information to
** ensure the GNU Lesser General Public License version 3 requirements
** will be met: https://www.gnu.org/licenses/lgpl-3.0.html.
**
** GNU General Public License Usage
** Alternatively, this file may be used under the terms of the GNU
** General Public License version 2.0 or (at your option) the GNU General
** Public license version 3 or any later version approved by the KDE Free
** Qt Foundation. The licenses are as published by the Free Software
** Foundation and appearing in the file LICENSE.GPL2 and LICENSE.GPL3
** included in the packaging of this file. Please review the following
** information to ensure the GNU General Public License requirements will
** be met: https://www.gnu.org/licenses/gpl-2.0.html and
** https://www.gnu.org/licenses/gpl-3.0.html.
**
** $QT_END_LICENSE$
**
****************************************************************************/

#ifndef ASQLITECIHPERDRIVER_H
#define ASQLITECIHPERDRIVER_H

// Precompiled includes

// System includes

// Qt includes
#include <QtSql/QSqlDriver>

// Application includes
#include <asqliteciphersecurebuffer.h>

// Constants and definitions
struct sqlite3;

#ifdef QT_PLUGIN
#define Q_EXPORT_SQLDRIVER_SQLITE
#else
#define Q_EXPORT_SQLDRIVER_SQLITE Q_SQL_EXPORT
#endif

// Classes
class QSqlResult;
class SQLiteCipherDriverPrivate;

QT_BEGIN_NAMESPACE

// Class definition
class Q_EXPORT_SQLDRIVER_SQLITE SQLiteCipherDriver : public QSqlDriver {

	Q_DECLARE_PRIVATE(SQLiteCipherDriver)
	Q_OBJECT
	friend class SQLiteResultPrivate;

	public:

		explicit SQLiteCipherDriver(QObject* parent = nullptr);
		explicit SQLiteCipherDriver(sqlite3* connection, QObject* parent = nullptr);
		~SQLiteCipherDriver(void);

		bool hasFeature(DriverFeature f) const override;
		bool open(
			const QString& db,const QString& user,
			const QString& password,
			const QString& host,
			int port,
			const QString& connOpts
		) override;
		void close(void) override;
		QSqlResult *createResult() const override;
		bool beginTransaction() override;
		bool commitTransaction() override;
		bool rollbackTransaction() override;
		QStringList tables(QSql::TableType) const override;
		QSqlRecord record(const QString& tablename) const override;
		QSqlIndex primaryIndex(const QString& table) const override;
		QVariant handle() const override;
		QString escapeIdentifier(const QString& identifier, IdentifierType) const override;
		bool subscribeToNotification(const QString& name) override;
		bool unsubscribeFromNotification(const QString& name) override;
		QStringList subscribedToNotifications() const override;

	private Q_SLOTS:

		void handleNotification(const QString& tableName, qint64 rowid);
};

QT_END_NAMESPACE

#endif // ASQLITECIHPERDRIVER_H
