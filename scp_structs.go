package goNessus

type ScpCredentials struct {
	Username string
	Password string
}

type ScpRemoteMachine struct {
	Host string
	Port string
}

type ScpKeyfile struct {
	Path     string
	Filename string
}
