# Work with pki secrets engine
#path "pki_int*"        { capabilities = [ "read", "list" ] }
#path "pki_int/sign/*"  { capabilities = [ "create", "update" ] }
#path "pki_int/issue/*" { capabilities = [ "create" ] }
path "pki_int*" { capabilities = [ "create", "read", "update", "delete", "list", "sudo", "patch" ]
}
