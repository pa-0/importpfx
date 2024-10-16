# `IMPORTPFX` v1.0 by Joe Klemencic

<sup><em>Simple standalone utility for importing `PKCS12` (`.pfx`) certificates into the certificate store and (optionally) overwriting any existing certificate from the same issuer.</em></sup>

### OVERVIEW

This utility will import a `PKCS12` certificate file (with a **`.p12`** or **`.pfx`** extension) into the certificate store specified by the `-s` parameter.
The default behavior is to overwrite a like certificates (if present in the same store). The `-r "Subject OU"` will remove all certificates in the target store matching the Subject CN
in the `PKCS12` file and the Subject OU set to the `-r` parameter.

### USAGE: 

```bat
importpfx.exe -f FILENAME.PFX -p PASSWORD -t USER|MACHINE -s CERTSTORE [-r "Subject OU to remove" | -all]
```

### PARAMETERS:

flag | description
--|--
`-f` | PKCS12 filename
`-p` | Password to secure the private key with
`-t` | Store type (USER or MACHINE)
`-s` | The certificate store to import into (MY is a common param)
`-r "Subject OU Text"` | Deletes all certs with _Subject OU_ matching `"Subject OU Text"` & _Subject CN_ matching `PKCS12` Subject CN
`-r -all` | Delete ALL user certificates in the <certstore>

### EXAMPLES:

1. #### IMPORT a PFX/PKCS12 file into the MY store, overwriting if allowed:
    
    ```bat
    importpfs.exe -f x509.p12 -p "password" -t USER -s MY
    ```

2. #### IMPORT a PFX/PKCS12 file into the local machine Testing store and delete any stored certificates with a Subject containing `OU="Self-Signed CA"`:
    
    ```bat
    importpfx.exe -f x509.p12 -p "" -t MACHINE -s Testing -r "Self-Signed CA"
    ```

3. #### Delete ALL certificates in the USER MY store:
    
    ```bat
    importpfx.exe -t USER -s MY -r -all
    ```
