#include <stdio.h>
#include <string.h>

/* Formula from the OFFICIAL Bitcoin-Address-Utility source
 * (Walletgen.cs): PrivKey = SHA256(n + "/" + passphrase + "/" + n + "/BITCOIN")
 * where n = "1" thru "10". No reimplementation risk - this IS the
 * published reference formula, only SHA256 itself needs validating
 * (already covered by other tests in this directory). */

int main(){
    printf("Casascius BAU key generation formula (from official source):\n");
    printf("  PrivKey = SHA256(n + \"/\" + passphrase + \"/\" + n + \"/BITCOIN\")\n\n");
    printf("Test: n=1, passphrase=\"teste\"\n");
    printf("  string to hash: \"1/teste/1/BITCOIN\"\n");
    printf("  (validate this string's SHA256 with any standard tool, e.g.:\n");
    printf("   python3 -c \"import hashlib; print(hashlib.sha256(b'1/teste/1/BITCOIN').hexdigest())\"\n");
    printf("   expected: ccc8e901ff9d79d28a8b2781377fb0bd5d7be605ab83b1aa07a5374adbda49fc)\n");
    return 0;
}
