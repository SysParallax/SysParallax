SET FOREIGN_KEY_CHECKS=0;
SOURCE /docker-entrypoint-initdb.d/source/demo_database.sql;
SET FOREIGN_KEY_CHECKS=1;
