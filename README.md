# go-nessus
Nessus 6 API Client written in Golang

Example target file:

```
requestid:  1
method: default
192.168.0.5/32
```

Example target file for multiple hosts:

```
requestid:  2
method: atomic
192.168.0.5/32
192.168.0.6/32
192.168.0.7/32
192.168.0.8/32
192.168.0.9/32
192.168.0.10/32
```
