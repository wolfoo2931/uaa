/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.db;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;

public class FixLegacyMySQLOauthCodeColumn {

    private static Log logger = LogFactory.getLog(FixLegacyMySQLOauthCodeColumn.class);

    private final DataSource dataSource;
    private final String type;
    private final JdbcTemplate template;
    private final String tableName = "oauth_code";
    private final String columnName = "code";

    public FixLegacyMySQLOauthCodeColumn(DataSource dataSource, String type) throws SQLException {
        this.dataSource = dataSource;
        this.type = type;
        template = new JdbcTemplate(dataSource);
    }

    public void checkMigration() throws SQLException {
        logger.debug(String.format("Evaluating DB type:%s", type));
        if (!isMySQL()) {
            logger.debug(String.format("Skipping 4.0.3 DB migration check for non MySQL DB[%s]", type));
            return;
        }
        int columnSize = getColumnSize(tableName, columnName);
        if (columnSize == -1) {
            logger.info("Unable to detect previous column size. Assuming new migration, skipping.");
            return;
        }
        logger.debug(String.format("%s.%s column size is %s", tableName, columnName, columnSize));
        if (columnSize >255) {
            logger.info(String.format("Changing %s.%s size to %s", tableName, columnName, 255));
            template.update("ALTER TABLE oauth_code MODIFY code VARCHAR(255)");
            logger.info(String.format("Completed %s.%s size is now %s", tableName, columnName, 255));
        }
        if (!hasFailed_4_0_3_Script()) {
            return;
        }

        logger.info("deleting failed 4.0.3 migration");
        deleteFailedMigration();
        logger.info("Failed migration deleted. Continuing.");
    }

    protected boolean isMySQL() {
        return "mysql".equals(type);
    }

    protected boolean hasFailed_4_0_3_Script() throws SQLException {
        if (getColumnSize("schema_version", "version") == -1) {
            logger.info("Unable to detect schema_version table. Assuming new migration, skipping.");
            return false;
        }
        return 1 == template.queryForObject("select count(*) from schema_version where version = '4.0.3' and success = ?", Integer.class, false);
    }

    protected int getVersionRank() {
        return template.queryForObject("select installed_rank from schema_version where version = '4.0.3' and success = ?", Integer.class, false);
    }

    protected void deleteFailedMigration() {
        template.update("delete from schema_version where version = '4.0.3' and success = ?", false);
    }

    public int getColumnSize(String tableName, String columnName) throws SQLException {

        try (
            Connection connection = dataSource.getConnection();
            ResultSet rs = connection.getMetaData().getColumns(connection.getCatalog(), null, null, null);
            ){
            while (rs.next()) {
                String rstableName = rs.getString("TABLE_NAME");
                String rscolumnName = rs.getString("COLUMN_NAME");
                int columnSize = rs.getInt("COLUMN_SIZE");
                if (tableName.equalsIgnoreCase(rstableName) && columnName.equalsIgnoreCase(rscolumnName)) {
                    return columnSize;
                }
            }
        }
        return -1;
    }


}
