# pwned-passwords-check

Use the k-anonimity api of api.pwnedpasswords.com to check if a hash, or list of hashes is present. 

This caches the entries from pwnedpasswords in a group of files, and opportunistically updates the files if the etag return by the service has changed. 


## Usage

```sh
go run main.go -hash "some NTLM hash"
go run main.go -file /path/to/list/of/ntlm/hashes

# Or

go build 

# then do the same thing

```