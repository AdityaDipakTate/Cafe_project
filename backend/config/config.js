require("dotenv").config();
module.exports = {
  development: {
    username: "postgres",
    password: "2004",
    database: "coffee_db",
    host: "127.0.0.1",
    dialect: "postgres"
  },
  test: {
    username: process.env.USERNAME,
    password: process.env.PASSWORD,
    database: process.env.DATABASENAME,
    host: "127.0.0.1",
    dialect: "postgres"
  },
  production: {
    username: process.env.USERNAME,
    password: process.env.PASSWORD, 
    database: process.env.DATABASENAME,
    host: "127.0.0.1",
    dialect: "postgres"
  }
};
