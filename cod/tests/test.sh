#!/bin/bash
# should be called from parent dir

tmpdir=$(mktemp -d)
trap "rm -rf ${tmpdir}" 0 1 2 3 15

echo "generating passwordless keys (and wasting entropy, don't do this often please)"
openssl genrsa -out ${tmpdir}/my1.key 4096 2>/dev/null || exit 1
openssl rsa -in ${tmpdir}/my1.key -pubout >> ${tmpdir}/my1.pub 2>/dev/null || exit 1

echo -n "testing short message: "
echo It works | ./cod e ${tmpdir}/my1.pub | ./cod d ${tmpdir}/my1.key || exit 1
echo "encrypting/decrypting self, output and orig hashsum follow: "
./cod e ${tmpdir}/my1.pub <crypto.c | ./cod d ${tmpdir}/my1.key | md5sum || exit 1
md5sum crypto.c
echo "testing various sized plaintexts"
for i in {0..42} {8170..8210} 1000000; do
    echo -ne "\r$i      "
    dd if=/dev/zero bs=$i count=1 2>/dev/null |
         ./cod e ${tmpdir}/my1.pub |
         ./cod d ${tmpdir}/my1.key >/dev/null || {
             echo "test failed"
             exit 1
         }
done
echo

echo "generating password-protected keys (such a waste of precious entropy :/)"
openssl genrsa -aes256 -passout pass:password -out ${tmpdir}/my.key 4096 2>/dev/null || exit 1
openssl rsa -passin pass:password -in ${tmpdir}/my.key -pubout >> ${tmpdir}/my.pub 2>/dev/null || exit 1
echo -n "testing short message: "
echo It works | ./cod e ${tmpdir}/my.pub | COD_PASSWORD=password ./cod d ${tmpdir}/my.key || exit 1
echo "encrypting/decrypting self, output and orig hashsum follow: "
./cod e ${tmpdir}/my.pub <crypto.c | COD_PASSWORD=password ./cod d ${tmpdir}/my.key | md5sum || exit 1
md5sum crypto.c
echo "testing various sized plaintexts"
for i in {0..42} {8170..8210} 1000000; do
  echo -ne "\r$i      "
  dd if=/dev/zero bs=$i count=1 2>/dev/null |
		 ./cod e ${tmpdir}/my.pub |
		 COD_PASSWORD=password ./cod d ${tmpdir}/my.key >/dev/null || {
           echo "test failed"
           exit 1
       }
done
echo
