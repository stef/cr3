#!/bin/sh
# this file should be run from the parent dir

echo "checking test vector"
./tests/sphincs-test || exit 1

tmpdir=$(mktemp -d)
trap "rm -rf ${tmpdir}" 0 1 2 3 15

echo "generating keys"
./sphincs g ${tmpdir}/asdf || exit 1

echo -n "testing: "
echo "hello world" |
    ./sphincs s ${tmpdir}/asdf.key |
    ./sphincs v ${tmpdir}/asdf.pub ||
    exit 1

echo running various sized tests
for i in {24500..24600} {48085..48090} 10000000; do
	 echo -ne "$i        \r"
	 dd if=/dev/zero bs=$i count=1 2>/dev/null |
		  ./sphincs s ${tmpdir}/asdf.key |
		  ./sphincs v ${tmpdir}/asdf.pub || {
           echo "test failed $i"
           exit 1
        }
done
#rm -rf ${tmpdir}
echo size tests ok
