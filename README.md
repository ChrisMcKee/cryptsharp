CryptSharp
==========

Install using NUGET - https://nuget.org/packages/CryptSharp/
==========

------------------

CryptSharp provides Blowfish, BCrypt, SCrypt, and PBKDF2 for any HMAC (.Net's built-in PBKDF2 implementation only supports SHA-1). 
If you are looking to store passwords in a database, BCrypt is much harder for an attacker to break than, say, simple MD5 or SHA-1.

You can get a vivid example of the differences in time-to-crack here: https://passfault.appspot.com/

Using CryptSharp is simple. To crypt a password, add the assembly to your references and type:

<pre><code>
using CryptSharp;
string crypted = Crypter.Blowfish.Crypt(keyBytes); //or
string crypted = Crypter.Blowfish.Crypt(keyBytes, Crypter.Blowfish.GenerateSalt(6));
</code></pre>

To test the crypted password against a potential password, use:

<pre><code>
using CryptSharp;
bool matches = (crypted == Crypter.Blowfish.Crypt(testKeyBytes, crypted));
</code></pre>

Be aware when using BCrypt that only the first 72 bytes of a password are used. This limitation is not specific to this implementation. If you are likely to pass byte arrays over 72 bytes in length, call PadKeyThenCrypt to have the extra bytes removed.

------------------
.Net Membership Provider
==========

If your looking for a way to shore up your .net Membership Provider without having to create your own implementation.
Take a look at https://github.com/skradel/Zetetic.Security ; it will greatly simplify the addition of
bcrypt to your SqlMembershipProvider (standard setup).

------------------

_GIT Clone of the source files in http://www.zer7.com/software.php?page=cryptsharp_

_CryptSharp uses the ISC license._
http://en.wikipedia.org/wiki/ISC_license

_Taken from the January 23, 2011 download._

Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
