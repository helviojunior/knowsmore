# Knows More

## Getting stats

```bash
knowsmore --stats
```

This command will produce several statistics about the passwords like the output bellow

```bash
KnowsMore v0.1.4 by Helvio Junior
Active Directory, BloodHound, NTDS hashes and Password Cracks correlation tool
https://github.com/helviojunior/knowsmore
    
 [+] Startup parameters
     command line: knowsmore --stats 
     module: stats
     database file: knowsmore.db
  
 [+] start time 2023-01-11 03:59:20
[?] General Statistics
+-------+----------------+-------+
|   top | description    |   qty |
|-------+----------------+-------|
|     1 | Total Users    | 95369 |
|     2 | Unique Hashes  | 74299 |
|     3 | Cracked Hashes | 23177 |
|     4 | Cracked Users  | 35078 |
+-------+----------------+-------+

 [?] General Top 10 passwords
+-------+-------------+-------+
|   top | password    |   qty |
|-------+-------------+-------|
|     1 | password    |  1111 |
|     2 | 123456      |   824 |
|     3 | 123456789   |   815 |
|     4 | guest       |   553 |
|     5 | qwerty      |   329 |
|     6 | 12345678    |   277 |
|     7 | 111111      |   268 |
|     8 | 12345       |   202 |
|     9 | secret      |   170 |
|    10 | sec4us      |   165 |
+-------+-------------+-------+
```

## Installation

```bash
pip3 install --upgrade git+https://github.com/helviojunior/knowsmore.git#egg=knowsmore
```

## Create database file

All data are stored in a SQLite Database

```bash
knowsmore --create-db
```

## Importing NTDS file

**Note:** First use the secretsdump to extract ntds hashes with the command bellow

```bash
secretsdump.py -ntds ntds.dit -system system.reg -hashes lmhash:ntlmhash LOCAL -outputfile ~/Desktop/client_name
```

After that import

```bash
knowsmore --ntlm-hash --import-ntds ~/Desktop/client_name.ntds
```

## Importing cracked hashes

### Cracking hashes

In order to crack the hashes i usualy use hashcat with the command bellow

```bash
# Extract NTLM hashes from file
cat ~/Desktop/client_name.ntds | cut -d ':' -f4 > ntlm_hashes.txt

# Wordlist attack
hashcat -m 1000 -a 0 -O -o "~/Desktop/cracked.txt" --remove "~/Desktop/ntlm_hash.txt" "~/Desktop/Wordlist/*"

# Mask attack
hashcat -m 1000 -a 3 -O --increment --increment-min 4 -o "~/Desktop/cracked.txt" --remove "~/Desktop/ntlm_hash.txt" ?a?a?a?a?a?a?a?a
```

### importing hashcat output file

```bash
knowsmore --ntlm-hash --import-cracked ~/Desktop/cracked.txt
```

## Importing BloodHound files

```bash
# Bloodhound ZIP File
knowsmore --bloodhound --import-data ~/Desktop/client.zip

# Bloodhound JSON File
knowsmore --bloodhound --import-data ~/Desktop/20220912105336_users.json
```

**Note:** The KnowsMore is able to import BloodHound ZIP File and JSON (users, domains and groups) files

# To do

[Check the TODO file](TODO.md)