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

namespace CryptSharp.Utility
{
	using System;
	using System.Collections.Generic;

	public static class HexBase16
	{
		public static int Decode(char value)
		{
			if (value >= '0' && value <= '9')
			{
				return 0 + (value - '0');
			}
			if (value >= 'A' && value <= 'F')
			{
				return 10 + (value - 'A');
			}
			if (value >= 'a' && value <= 'f')
			{
				return 10 + (value - 'a');
			}
			return 0;
		}

		public static byte[] Decode(char[] value)
		{
			return Pow2Base.Decode(4, Decode, value);
		}

		public static byte[] Decode(IEnumerable<char> value, int bitsToDecode)
		{
			return Pow2Base.Decode(4, Decode, value, bitsToDecode);
		}

		public static char Encode(int value)
		{
			try
			{
				return "0123456789ABCDEF"[value];
			}
			catch (IndexOutOfRangeException)
			{
				throw new ArgumentException("value");
			}
		}

		public static char[] Encode(byte[] value)
		{
			return Pow2Base.Encode(4, Encode, value);
		}

		public static char[] Encode(byte[] value, int bitsToEncode)
		{
			return Pow2Base.Encode(6, Encode, value, bitsToEncode);
		}
	}
}