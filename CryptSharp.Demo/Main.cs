#region License

/*
Illusory Studios C# Crypto Library (CryptSharp)
Copyright (c) 2010 James F. Bellinger <jfb@zer7.com>

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

namespace CryptSharp.Demo
{
	using System;
	using System.Text;
	using SCrypt;

	internal class MainClass
	{
		public static void Main(string[] args)
		{
			TestVectors.Test();
			Blowfish.TestVectors.Test();
			BCrypt.TestVectors.Test();
			Pbkdf2.TestVectors.Test();

			Console.WriteLine("Now a simple BCrypt demo");
			string crypt = Crypter.Blowfish.GenerateSalt();
			Console.WriteLine(crypt);

			for (int i = 0; i < 10; i ++)
			{
				// Try this against PHP's crypt('password', 'output of this function')
				byte[] pwkey = Encoding.ASCII.GetBytes("Hello World!");
				crypt = Crypter.Blowfish.PadKeyThenCrypt(pwkey, crypt);
				// .Crypt alone is fine, but may raise an error if the key is too large or small.
				// BCrypt has a max length of int.MaxValue-1 here, so it isn't a problem.

				Array.Clear(pwkey, 0, pwkey.Length); // It may get paged to disk, so be sure to clear the plain-text password.
				Console.WriteLine(crypt);
			}

			Console.WriteLine("Press Enter to exit");
			Console.ReadLine();
		}
	}
}