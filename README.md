mod_rivta
=========

Apache mod that read SOAP payload header logical-address(HSAid) and xml namespace 'Responder' on incoming request and out filer read replay <faultstring>, http error and be change to soap:Fault.
Mainly used for logging purposes but can be use for access control.
Mod is base on ssl module code from apache2.4.

Request soap header, to|logicaladdress is read to env variable rivta_to_hsaid (singel or mulit, split on #)
Reply error is assume to be in VPXXX format and is read to env variable rivta_vp_error else variable get value 'Error'
Read namespace from 'Responder:[n]'

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

#Enable soap faultstring format on out filter
RivtaEnabledToSoapFault On

Config ex:
...
LoadModule rivta_module modules/mod_rivta.so
...
LogFormat %{rivta_to_hsaid}e, %{rivta_to_hsaid1}e, %{rivta_to_hsaid2}e ...
LogFormat %{rivta_vp_error}e
LogFormat %{rivta_namespace}e
...
<Location /some/>
  RivtaEnabled On
  RivtaEnabledError On
  RivtaEnabledToSoapFault On
  
  SSLRequire 		%{ENV:rivta_to_hsaid} eq "HSAid"
</Location>
```
