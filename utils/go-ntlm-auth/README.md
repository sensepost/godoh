# go-ntlm-auth

This is an implementation of NTLM for Go that was implemented using Windows SSPI
(Security Support Provider Interface). It differs from other implemenations of
NTLM as it uses the default credentials of the account that the application is
running with, meaning the username and password does not have to be provided in
plain text.

## Usage Notes

This is currently only implemented for Windows.

### References
https://github.com/G-Research/go-ntlm-auth - original author
https://github.com/denisenkom/go-mssqldb - sspi_windows.go used as ntlm_windows.go to perform Win32 calls to SSPI
https://github.com/github/git-lfs/blob/master/lfs/ntlm.go - git-lfs used as basis for NTLM authentication logic
