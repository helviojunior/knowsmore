# Knows More

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

