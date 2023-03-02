#Imports
import sys
import subprocess
from datetime import datetime
import csv

time = datetime.now()
current_time = time.strftime("%Y%m%d-%H%M%S")

#Vulnerable protocols and ciphers
weak_protocols = ["SSLv2","SSLv3","TLSv1.0","TLSv1.1"]
sweet32 = ["IDEA-CBC-SHA","IDEA-CBC-MD5","RC2-CBC-MD5","KRB5-IDEA-CBC-SHA","KRB5-IDEA-CBC-MD5","ECDHE-RSA-DES-CBC3-SHA","ECDHE-ECDSA-DES-CBC3-SHA","SRP-DSS-3DES-EDE-CBC-SHA","SRP-RSA-3DES-EDE-CBC-SHA","SRP-3DES-EDE-CBC-SHA","EDH-RSA-DES-CBC3-SHA","EDH-DSS-DES-CBC3-SHA","DH-RSA-DES-CBC3-SHA","DH-DSS-DES-CBC3-SHA","AECDH-DES-CBC3-SHA","ADH-DES-CBC3-SHA","ECDH-RSA-DES-CBC3-SHA","ECDH-ECDSA-DES-CBC3-SHA","DES-CBC3-SHA","DES-CBC3-MD5","DES-CBC3-SHA","RSA-PSK-3DES-EDE-CBC-SHA","PSK-3DES-EDE-CBC-SHA","KRB5-DES-CBC3-SHA","KRB5-DES-CBC3-MD5","ECDHE-PSK-3DES-EDE-CBC-SHA","DHE-PSK-3DES-EDE-CBC-SHA","DES-CFB-M1","EXP1024-DHE-DSS-DES-CBC-SHA","EDH-RSA-DES-CBC-SHA","EDH-DSS-DES-CBC-SHA","DH-RSA-DES-CBC-SHA","DH-DSS-DES-CBC-SHA","ADH-DES-CBC-SHA","EXP1024-DES-CBC-SHA","DES-CBC-SHA","EXP1024-RC2-CBC-MD5","DES-CBC-MD5","DES-CBC-SHA","KRB5-DES-CBC-SHA","KRB5-DES-CBC-MD5","EXP-EDH-RSA-DES-CBC-SHA","EXP-EDH-DSS-DES-CBC-SHA","EXP-ADH-DES-CBC-SHA","EXP-DES-CBC-SHA","EXP-RC2-CBC-MD5","EXP-RC2-CBC-MD5","EXP-KRB5-RC2-CBC-SHA","EXP-KRB5-DES-CBC-SHA","EXP-KRB5-RC2-CBC-MD5","EXP-KRB5-DES-CBC-MD5","EXP-DH-DSS-DES-CBC-SHA","EXP-DH-RSA-DES-CBC-SHA"]
BEAST = ["EXP-RC2-CBC-MD5","IDEA-CBC-SHA","EXP-DES-CBC-SHA","DES-CBC-SHA","DES-CBC3-SHA","EXP-DH-DSS-DES-CBC-SHA","DH-DSS-DES-CBC-SHA","DH-DSS-DES-CBC3-SHA","EXP-DH-RSA-DES-CBC-SHA","DH-RSA-DES-CBC-SHA","DH-RSA-DES-CBC3-SHA","EXP-EDH-DSS-DES-CBC-SHA","EDH-DSS-DES-CBC-SHA","EDH-DSS-DES-CBC3-SHA","EXP-EDH-RSA-DES-CBC-SHA","EDH-RSA-DES-CBC-SHA","EDH-RSA-DES-CBC3-SHA","EXP-ADH-DES-CBC-SHA","ADH-DES-CBC-SHA","ADH-DES-CBC3-SHA","KRB5-DES-CBC-SHA","KRB5-DES-CBC3-SHA","KRB5-IDEA-CBC-SHA","KRB5-DES-CBC-MD5","KRB5-DES-CBC3-MD5","KRB5-IDEA-CBC-MD5","EXP-KRB5-DES-CBC-SHA","EXP-KRB5-RC2-CBC-SHA","EXP-KRB5-DES-CBC-MD5","EXP-KRB5-RC2-CBC-MD5","AES128-SHA","DH-DSS-AES128-SHA","DH-RSA-AES128-SHA","DHE-DSS-AES128-SHA","DHE-RSA-AES128-SHA","ADH-AES128-SHA","AES256-SHA","DH-DSS-AES256-SHA","DH-RSA-AES256-SHA","DHE-DSS-AES256-SHA","DHE-RSA-AES256-SHA","ADH-AES256-SHA","CAMELLIA128-SHA","DH-DSS-CAMELLIA128-SHA","DH-RSA-CAMELLIA128-SHA","DHE-DSS-CAMELLIA128-SHA","DHE-RSA-CAMELLIA128-SHA","ADH-CAMELLIA128-SHA","EXP1024-RC2-CBC-MD5","EXP1024-DES-CBC-SHA","EXP1024-DHE-DSS-DES-CBC-SHA","CAMELLIA256-SHA","DH-DSS-CAMELLIA256-SHA","DH-RSA-CAMELLIA256-SHA","DHE-DSS-CAMELLIA256-SHA","DHE-RSA-CAMELLIA256-SHA","ADH-CAMELLIA256-SHA","PSK-3DES-EDE-CBC-SHA","PSK-AES128-CBC-SHA","PSK-AES256-CBC-SHA","DHE-PSK-3DES-EDE-CBC-SHA","DHE-PSK-AES128-CBC-SHA","DHE-PSK-AES256-CBC-SHA","RSA-PSK-3DES-EDE-CBC-SHA","RSA-PSK-AES128-CBC-SHA","RSA-PSK-AES256-CBC-SHA","SEED-SHA","DH-DSS-SEED-SHA","DH-RSA-SEED-SHA","DHE-DSS-SEED-SHA","DHE-RSA-SEED-SHA","ADH-SEED-SHA","PSK-AES128-CBC-SHA256","PSK-AES256-CBC-SHA384","DHE-PSK-AES128-CBC-SHA256","DHE-PSK-AES256-CBC-SHA384","RSA-PSK-AES128-CBC-SHA256","RSA-PSK-AES256-CBC-SHA384","ECDH-ECDSA-DES-CBC3-SHA","ECDH-ECDSA-AES128-SHA","ECDH-ECDSA-AES256-SHA","ECDHE-ECDSA-DES-CBC3-SHA","ECDHE-ECDSA-AES128-SHA","ECDHE-ECDSA-AES256-SHA","ECDH-RSA-DES-CBC3-SHA","ECDH-RSA-AES128-SHA","ECDH-RSA-AES256-SHA","ECDHE-RSA-DES-CBC3-SHA","ECDHE-RSA-AES128-SHA","ECDHE-RSA-AES256-SHA","AECDH-DES-CBC3-SHA","AECDH-AES128-SHA","AECDH-AES256-SHA","SRP-3DES-EDE-CBC-SHA","SRP-RSA-3DES-EDE-CBC-SHA","SRP-DSS-3DES-EDE-CBC-SHA","SRP-AES-128-CBC-SHA","SRP-RSA-AES-128-CBC-SHA","SRP-DSS-AES-128-CBC-SHA","SRP-AES-256-CBC-SHA","SRP-RSA-AES-256-CBC-SHA","SRP-DSS-AES-256-CBC-SHA","ECDHE-PSK-3DES-EDE-CBC-SHA","ECDHE-PSK-AES128-CBC-SHA","ECDHE-PSK-AES256-CBC-SHA","ECDHE-PSK-AES128-CBC-SHA256","ECDHE-PSK-AES256-CBC-SHA384","PSK-CAMELLIA128-SHA256","PSK-CAMELLIA256-SHA384","DHE-PSK-CAMELLIA128-SHA256","DHE-PSK-CAMELLIA256-SHA384","RSA-PSK-CAMELLIA128-SHA256","RSA-PSK-CAMELLIA256-SHA384","ECDHE-PSK-CAMELLIA128-SHA256","ECDHE-PSK-CAMELLIA256-SHA384"]
RC4 = ["ECDHE-RSA-RC4-SHA","ECDHE-ECDSA-RC4-SHA","DHE-DSS-RC4-SHA","AECDH-RC4-SHA","ADH-RC4-MD5","ECDH-RSA-RC4-SHA","ECDH-ECDSA-RC4-SHA","RC4-SHA","RC4-MD5","RC4-MD5","RSA-PSK-RC4-SHA","PSK-RC4-SHA","KRB5-RC4-SHA","KRB5-RC4-MD5","ECDHE-PSK-RC4-SHA","DHE-PSK-RC4-SHA","EXP1024-DHE-DSS-RC4-SHA","EXP1024-RC4-SHA","EXP1024-RC4-MD5","EXP-ADH-RC4-MD5","EXP-RC4-MD5","EXP-RC4-MD5","EXP-KRB5-RC4-SHA","EXP-KRB5-RC4-MD5"]

#Issue storage
weak_protocols_in_use = []
sweet32_ciphers_in_use = {}
BEAST_ciphers_in_use = {}
RC4_ciphers_in_use = {}
No_FS_ciphers_in_use = {}

#Start of Main function
def main():
   if len(sys.argv) == 1:
      print("Usage: python3 sslscanner.py [-h] [-t Target]")
      sys.exit(1)
   
   if sys.argv[1] == "-h":
      print("Usage: python3 sslscanner.py [-h] [-t Target]")
      print("-h: Print program usage")
      print("-t Target: Target for scanning")
      sys.exit(0)

   if sys.argv[1] == "-t":
      if len(sys.argv) < 3:
         print("Error: target argument missing")
         print("Usage: python3 sslscanner.py [-h] [-t Target]")
         sys.exit(1)

      target = sys.argv[2]

      filename = target+"_sslscan_output.txt"

      f = open(filename, "w")
      subprocess.run(["sslscan", "--no-colour", target], stdout=f)

      with open(filename, "r") as file:
         for line in file:
            if line.startswith("Accepted") or line.startswith("Preferred"):
               protocol = line.split()[1]
               if protocol not in weak_protocols_in_use and protocol in weak_protocols:
                  weak_protocols_in_use.append(protocol)
               
               cipher = line.split()[4]
               if cipher not in sweet32_ciphers_in_use and cipher in sweet32:
                  if protocol not in sweet32_ciphers_in_use:
                     sweet32_ciphers_in_use[protocol] = [cipher]
                  else:
                     sweet32_ciphers_in_use[protocol] += [cipher]
               
               if cipher not in BEAST_ciphers_in_use and cipher in BEAST and protocol in "TLSv1.0 SSLv3": 
                  if protocol not in BEAST_ciphers_in_use:
                     BEAST_ciphers_in_use[protocol] = [cipher]
                  else:
                     BEAST_ciphers_in_use[protocol] += [cipher]
               
               if cipher not in RC4_ciphers_in_use and cipher in RC4:
                  if protocol not in RC4_ciphers_in_use:
                     RC4_ciphers_in_use[protocol] = [cipher]
                  else:
                     RC4_ciphers_in_use[protocol] += [cipher]
               
               if "DHE" not in cipher and protocol not in "TLSv1.3":
                  if protocol not in No_FS_ciphers_in_use:
                     No_FS_ciphers_in_use[protocol] = [cipher]
                  else:
                     No_FS_ciphers_in_use[protocol] += [cipher]
         
         return RC4_ciphers_in_use, BEAST_ciphers_in_use, sweet32_ciphers_in_use, weak_protocols_in_use
            
   else:
      print("Error: Invalid argument")
      print("Usage: python myscript.py [-h] [-f filename]")
      sys.exit(1)


def issues():
   if len(weak_protocols_in_use) == 0:
      print("No weak protocols")
   else:  
      print("Weak protocols:") 
      for protocol in weak_protocols_in_use:
         print(protocol)
   print()
   
   if len(BEAST_ciphers_in_use) == 0:
      print("No ciphers vulnerable to BEAST")
   else:  
      print("Ciphers in use that are vulnerable to BEAST:") 
      print(BEAST_ciphers_in_use) 
   print()
   
   if len(sweet32_ciphers_in_use) == 0:
      print("No ciphers vulnerable to SWEET32")
   else:  
      print("Ciphers in use that are vulnerable to SWEET32:") 
      print(sweet32_ciphers_in_use)
   print()
   
   if len(RC4_ciphers_in_use) == 0:
      print("No RC4 ciphers")
   else:  
      print("Ciphers in use that are vulnerable to BIAS:") 
      print(RC4_ciphers_in_use)
   print()
   
   if len(No_FS_ciphers_in_use) == 0:
      print("All ciphers support PFS")
   else:  
      print("Ciphers that do not support PFS:")
      print(No_FS_ciphers_in_use) 
   
   with open(current_time+"-sslscan-results.csv", "a", newline='') as output:
      output_writer = csv.writer(output)
      output_writer.writerow(["Vulnerability","Protocol","Supported ciphers"])

      for key, values in BEAST_ciphers_in_use.items():
         output_writer.writerow(["BEAST",key,""])
         for value in values:
            output_writer.writerow(["","",value])      

      for key, values in sweet32_ciphers_in_use.items():
         output_writer.writerow(["Sweet32",key,""])
         for value in values:
            output_writer.writerow(["","",value])

      for key, values in RC4_ciphers_in_use.items():
         output_writer.writerow(["RC4",key,""])
         for value in values:
            output_writer.writerow(["","",value])      

      for key, values in No_FS_ciphers_in_use.items():
         output_writer.writerow(["Does not support PFS",key,""])
         for value in values:
            output_writer.writerow(["","",value])

main()
issues()
