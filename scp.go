package goNessus

import (
	"bytes"
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"io/ioutil"
	"log"
	"net"
	"os"
)

func getAgent() (agent.Agent, error) {
	agentConn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	return agent.NewClient(agentConn), err
}

func withAgentSshConfig(username string) *ssh.ClientConfig {
	agent, err := getAgent()
	if err != nil {
		log.Println("Failed to connect to SSH_AUTH_SOCK:", err)
		os.Exit(1)
	}
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeysCallback(agent.Signers),
		},
	}
	return config
}

func withoutAgentSshConfig(username string, scpKeyFile ScpKeyfile) *ssh.ClientConfig {
	keyFilePath := fmt.Sprintf("%s/%s", scpKeyFile.Path, scpKeyFile.Filename)
	keyFileContents, err := ioutil.ReadFile(keyFilePath)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
	signer, err := ssh.ParsePrivateKey(keyFileContents)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}

	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
	}

	return config
}

func Scp(scpKeyFile ScpKeyfile, scpCredentials ScpCredentials, scpRemoteMachine ScpRemoteMachine, usingSshAgent bool) {
	cmd := "/usr/bin/whoami"

	// An SSH client is represented with a ClientConn.
	//
	// To authenticate with the remote server you must pass at least one
	// implementation of AuthMethod via the Auth field in ClientConfig.
	var config *ssh.ClientConfig
	if usingSshAgent {
		config = withAgentSshConfig(scpCredentials.Username)
	} else {
		config = withoutAgentSshConfig(scpCredentials.Username, scpKeyFile)
	}

	client, err := ssh.Dial("tcp", scpRemoteMachine.Host+":"+scpRemoteMachine.Port, config)
	if err != nil {
		log.Print("Failed to dial: " + err.Error())
		os.Exit(1)
	}

	// Each ClientConn can support multiple interactive sessions,
	// represented by a Session.
	session, err := client.NewSession()
	if err != nil {
		log.Print("Failed to create session: " + err.Error())
		os.Exit(1)
	}
	defer session.Close()

	// Once a Session is created, you can execute a single command on
	// the remote side using the Run method.
	var b bytes.Buffer
	session.Stdout = &b
	if err := session.Run(cmd); err != nil {
		panic("Failed to run: " + err.Error())
	}
	fmt.Print(b.String())
}
