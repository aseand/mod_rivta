mod_rivta
=========

Apache mod that read SOPA payload header logical-address(HSAid) on incoming request and read replay <faultstring> on http error.
Mainly used for logging purposes but can be use for access control.

Request to|logicaladdress is read to env variable rivta_to_hsaid.
Reply error is assume to be in VPXXX format and is read to env variable rivta_vp_error else variable get value 'Error' 

See [RIVTA](http://rivta.se/) for ref

=========
```
Load mod:
LoadModule rivta_module modules/mod_rivta.so

Config per location:

#Enable read header
RivtaEnabled On

#Enable read reply error (http status >400)
RivtaEnabledError On

#Enable read reply error (http status >500)
RivtaEnabledError 500

Config ex:
...
LoadModule rivta_module modules/mod_rivta.so
...
LogFormat "\"%{rivta_to_hsaid}e\",\"%{rivta_vp_error}e\""
...
<Location /some/>
  RivtaEnabled On
  RivtaEnabledError On
  
  SSLRequire 		%{ENV:rivta_to_hsaid} eq "HSAid"
</Location>
```
