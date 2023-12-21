## Our SQL Database
We use postgres for our database implementation. `sqlx` as our Rust binding to make SQL queries. The table schemas are defined by the .sql file in `key-mgmt/persistence/migrations/`.

### Postgres Implementation
This directory implements a Rust crate: `lock-keeper-postgres`. The Lock-Keeper server defines
a trait used for storage: `DataStore` in `lock-keeper-key-server/src/server/database.rs`. We
implement this trait for postgres. **Note**: This trait was originally designed so we could plug in
different DB implementations into our server. This is probably unnecessary and later we may consider
just removing this trait.