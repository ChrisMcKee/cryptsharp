#region License

/*
Illusory Studios C# Crypto Library (CryptSharp)
Copyright (c) 2011 James F. Bellinger <jfb@zer7.com>

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

#endregion

namespace CryptSharp.Demo.Pbkdf2
{
	using System;
	using System.Security.Cryptography;
	using System.Text;
	using Utility;

	// Data Source: http://tools.ietf.org/html/draft-josefsson-pbkdf2-test-vectors-02#page-3
	internal static class TestVectors
	{
		private static void TestSHA1(string password, string salt, int c, int len,
		                             string expected)
		{
			Console.Write(".");

			byte[] derivedBytes = new byte[len];
			Pbkdf2.ComputeKey
				(Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(salt),
				 c, Pbkdf2.CallbackFromHmac<HMACSHA1>(), 20, derivedBytes);

			expected = expected
				.Replace(" ", "")
				.Replace("\r", "")
				.Replace("\n", "")
				.Replace("\t", "")
				.ToUpper();
			string derived = new string(HexBase16.Encode(derivedBytes));
			if (expected != derived)
			{
				Console.WriteLine("WARNING: PBKDF2 failed test ({0} instead of {1})", derived, expected);
			}
		}

		public static void Test()
		{
			Console.Write("Testing PBKDF2");
			TestSHA1("password", "salt", 1, 20,
			         @"0c 60 c8 0f 96 1f 0e 71
                f3 a9 b5 24 af 60 12 06
                2f e0 37 a6");
			TestSHA1("password", "salt", 2, 20,
			         @"ea 6c 01 4d c7 2d 6f 8c
                cd 1e d9 2a ce 1d 41 f0
                d8 de 89 57");
			TestSHA1("password", "salt", 4096, 20,
			         @"4b 00 79 01 b7 65 48 9a
                be ad 49 d9 26 f7 21 d0
                65 a4 29 c1");
			TestSHA1("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25,
			         @"3d 2e ec 4f e4 1c 84 9b
                80 c8 d8 36 62 c0 e4 4a
                8b 29 1a 96 4c f2 f0 70
                38");
			TestSHA1("pass\0word", "sa\0lt", 4096, 16,
			         @"56 fa 6a a7 55 48 09 9d
                  cc 37 d7 f0 34 25 e0 c3");
			Console.WriteLine("done.");
		}
	}
}