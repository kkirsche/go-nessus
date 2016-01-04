package goNessus

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"github.com/kkirsche/go-nessus/Godeps/_workspace/src/github.com/go-sql-driver/mysql"
	_ "github.com/kkirsche/go-nessus/Godeps/_workspace/src/github.com/mattn/go-sqlite3"
	"io/ioutil"
	"log"
)

// Generates a secure or insecure TCP MySQL database connection on port 3306
func ConnectToMySqlDatabase(username string, password string, database string, server string, INFO map[string]string, secure bool) *sql.DB {
	if secure {
		rootCertPool := x509.NewCertPool()
		pem, err := ioutil.ReadFile(INFO["ScriptDirectory"] + "/certs/cacert.pem")
		if err != nil {
			log.Fatal("Failed to open ca cert: " + err.Error())
		}
		if ok := rootCertPool.AppendCertsFromPEM(pem); !ok {
			log.Fatal("Failed to append PEM.")
		}
		clientCert := make([]tls.Certificate, 0, 1)
		certs, err := tls.LoadX509KeyPair(INFO["ScriptDirectory"]+"/certs/client-cert.pem", INFO["ScriptDirectory"]+"/certs/client-key.pem")
		if err != nil {
			log.Fatal("Failed to load x509 client cert and key: " + err.Error())
		}
		clientCert = append(clientCert, certs)
		mysql.RegisterTLSConfig("custom", &tls.Config{
			RootCAs:      rootCertPool,
			Certificates: clientCert,
		})
		db, err := sql.Open("mysql", username+password+"@tcp("+server+":3306)/"+database+"?tls=skip-verify")
		if err != nil {
			log.Fatal("Couldn't connect to database: " + err.Error())
		}
		return db
	} else {
		db, err := sql.Open("mysql", username+password+"@tcp("+server+":3306)/"+database)
		if err != nil {
			log.Fatal("Couldn't connect to database: " + err.Error())
		}
		return db
	}
}

// Generates a file connection to an SQLite3 database connection
func ConnectToSqliteDatabase(sqlite_db string) *sql.DB {
	db, err := sql.Open("sqlite3", "file:"+sqlite_db)
	if err != nil {
		log.Fatal("Couldn't connect to database: " + err.Error())
	}
	return db
}
