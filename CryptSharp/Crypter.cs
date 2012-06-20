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

namespace CryptSharp
{
	using System;
	using System.Security.Cryptography;
	using Utility;

	public abstract class Crypter
	{
		static Crypter()
		{
			Blowfish = new BlowfishCrypter();
		}

		public abstract int MaxKeyLength { get; }

		public abstract int MinKeyLength { get; }

		public static BlowfishCrypter Blowfish { get; private set; }

		public string Crypt(byte[] key)
		{
			return Crypt(key, GenerateSalt());
		}

		public abstract string Crypt(byte[] key, string salt);

		public abstract string GenerateSalt();

		public abstract string GenerateSalt(int rounds);

		protected static byte[] GenerateSaltBytes(int saltLength)
		{
			Helper.CheckRange("saltLength", saltLength, 0, int.MaxValue);
			var rng = new RNGCryptoServiceProvider();
			var salt = new byte[saltLength];
			rng.GetBytes(salt);
			return salt;
		}

		public byte[] PadKeyForCrypt(byte[] key, out bool padded)
		{
			Helper.CheckNull("key", key);
			int newLength = Math.Min(MaxKeyLength, Math.Max(MinKeyLength, key.Length));
			padded = newLength != key.Length;
			if (padded)
			{
				Array.Resize(ref key, newLength);
			}
			return key;
		}

		public string PadKeyThenCrypt(byte[] key)
		{
			return PadKeyThenCrypt(key, GenerateSalt());
		}

		public string PadKeyThenCrypt(byte[] key, string salt)
		{
			bool padded;
			byte[] newKey = PadKeyForCrypt(key, out padded);
			string result = Crypt(newKey, salt);
			if (padded)
			{
				Array.Clear(newKey, 0, newKey.Length);
			}
			return result;
		}

		protected void CheckKey(byte[] key)
		{
			Helper.CheckRange("key", key, MinKeyLength, MaxKeyLength);
		}
	}
}