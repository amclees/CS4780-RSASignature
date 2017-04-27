# CS4780-RSASignature

RSASignature is a simple RSA/MD5 based signature system based on RSA with an ~1024 bit n. It uses Java's BigInteger
class to handle many operations involved in RSA.

Though it is perhaps more secure than no security system, neither MD5 nor a pure RSA digital signature system is secure,
so naturally neither is RSASignature. MD5 collisions have been demonstrated for documents and pure an RSA signature system
allows for multiple valid signatures.
