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

namespace CryptSharp.Demo.Blowfish
{
	using System;
	using System.IO;
	using System.Reflection;
	using System.Text.RegularExpressions;
	using Utility;

	internal static class TestVectors
	{
		public static void Test()
		{
			Console.Write("Testing Blowfish");
			using (Stream stream =
				Assembly.GetExecutingAssembly().GetManifestResourceStream
					("CryptSharp.Demo.Blowfish.TestVectors.txt"))
			{
				using (var reader = new StreamReader(stream))
				{
					string line;
					while ((line = reader.ReadLine()) != null)
					{
						Match match = Regex.Match(line, @"^([0-9A-z]{16})\s*([0-9A-z]{16})\s*([0-9A-z]{16})$");
						if (!match.Success)
						{
							continue;
						}

						string key = match.Groups[1].Value, clear = match.Groups[2].Value, cipher = match.Groups[3].Value;
						byte[] keyBytes = HexBase16.Decode(key.ToCharArray());
						byte[] clearBytes = HexBase16.Decode(clear.ToCharArray());

						Console.Write(".");
						using (BlowfishCipher fish = BlowfishCipher.Create(keyBytes))
						{
							var testCipherBytes = new byte[8];
							fish.Encipher(clearBytes, 0, testCipherBytes, 0);
							var testCipher = new string(HexBase16.Encode(testCipherBytes));
							if (cipher != testCipher)
							{
								Console.WriteLine("WARNING: Encipher failed test ({0} became {1})", cipher, testCipher);
							}

							var testClearBytes = new byte[8];
							fish.Decipher(testCipherBytes, 0, testClearBytes, 0);
							var testClear = new string(HexBase16.Encode(testClearBytes));
							if (clear != testClear)
							{
								Console.WriteLine("WARNING: Decipher failed ({0} became {1})", clear, testClear);
							}
						}
					}
				}
			}

			Console.WriteLine("done.");
		}
	}
}