## Importers:
* [x] Import NTLM Hashes from NTDS file from impacket secretsdump 
* [x] Import Cracked NTLM hashes from hashcat output file
* [x] Import BloodHound ZIP oe JSON file
* [x] Import Domain data from BloodHound
* [x] Import User data from BloodHound
* [x] Import Group data from BloodHound
* [ ] Import Domain data from Powershell MSOnline module
* [ ] Import User data from Powershell MSOnline module
* [ ] Import Group data from Powershell MSOnline module
* [ ] Import NTLM Hashes from CrackMapExec output file 
* [ ] Import Cracked NTLM hashes from John the Ripper output file

## Analysers
* [x] Analyse the quality of password (length , lower case, upper case, digit, special and latin)
* [x] Analyse similarity of password with company name


## Finders
* [x] Search for users
* [x] Search for user password (Hash a clear-text)
* [x] Search filter from cracked only passwords

## Statistics
* [x] Generate Top 10 cracked passwords 
* [x] Generate Top 10 cracked passwords by domain

## Exporters
* [x] Export data to JSON file
* [ ] Export data to ElasticSearch
* [ ] Export data to Splunk
* [ ] Export Password Spray list
