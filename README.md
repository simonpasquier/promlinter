# promlinter

A basic linter for Prometheus rules. It retrieves rules from the Prometheus v1
API, parses the queries and warns about queries that reference metric names not
collected by the server.
