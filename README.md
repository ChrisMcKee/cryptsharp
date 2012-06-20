CryptSharp
==========

GIT Clone of the source files in http://www.zer7.com/software.php?page=cryptsharp

------------------

CryptSharp provides Blowfish, BCrypt, SCrypt, and PBKDF2 for any HMAC (.Net's built-in PBKDF2 implementation supports only SHA-1). If you are looking to store passwords in a database, BCrypt is much harder for an attacker to break than, say, simple MD5 or SHA-1. I recommend it.

Using CryptSharp is simple. To crypt a password, add the assembly to your references and type:
<pre><code>
using CryptSharp
string crypted = Crypter.Blowfish.Crypt(keyBytes); or
string crypted = Crypter.Blowfish.Crypt(keyBytes, Crypter.Blowfish.GenerateSalt(6));
</code></pre>

To test the crypted password against a potential password, use:
<pre><code>
using CryptSharp;
bool matches = (crypted == Crypter.Blowfish.Crypt(testKeyBytes, crypted));
Be aware when using BCrypt that only the first 72 bytes of a password are used. This limitation is not specific to my implementation. If you are likely to pass byte arrays over 72 bytes in length, call PadKeyThenCrypt to have the extra bytes removed.
</code></pre>


_CryptSharp uses the ISC license._

Taken from the January 23, 2011 download.