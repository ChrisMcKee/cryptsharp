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

namespace CryptSharp.Demo.BCrypt
{
	using System;
	using System.IO;
	using System.Reflection;
	using System.Text;
	using System.Text.RegularExpressions;

	internal static class TestVectors
	{
		public static void Test()
		{
			Console.Write("Testing BCrypt");
			using (Stream stream =
				Assembly.GetExecutingAssembly().GetManifestResourceStream
					("CryptSharp.Demo.BCrypt.TestVectors.txt"))
			{
				using (var reader = new StreamReader(stream))
				{
					string line;
					while ((line = reader.ReadLine()) != null)
					{
						Match match = Regex.Match(line, @"^([^,]*),(" + BlowfishCrypter.Regex + ")$");
						if (!match.Success)
						{
							continue;
						}

						// NOTE: PadKeyThenCrypt just makes sure the length is valid.
						//       For BCrypt, this is 0-72 bytes, because BCrypt (due to
						//       how it works) only uses the first 72 bytes. The Crypter
						//       MaximumLength property tells you how much will actually
						//       be used for an algorithm. If you know your passwords will
						//       always be of valid lengths, just call Crypt.
						string password = match.Groups[1].Value, crypt = match.Groups[2].Value;
						string testCrypt = Crypter.Blowfish.PadKeyThenCrypt(Encoding.UTF8.GetBytes(password), crypt);
						if (crypt != testCrypt)
						{
							Console.WriteLine("WARNING: Crypt failed ({0} instead of {1})", testCrypt, crypt);
						}
						Console.Write(".");
					}
				}
			}

			Console.WriteLine("done.");
		}
	}
}