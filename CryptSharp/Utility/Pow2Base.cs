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
	using System.Diagnostics;

	public static class Pow2Base
	{
		#region Delegates

		public delegate int DecodeCallback(char value);

		public delegate char EncodeCallback(int value);

		#endregion

		public static byte[] Decode(int bitsPerChar, DecodeCallback decodeCallback,
		                            char[] value)
		{
			Helper.CheckRange("bitsPerChar", bitsPerChar, 1, 8);
			Helper.CheckNull("value", value);
			Helper.CheckRange("value", value, 0, int.MaxValue/bitsPerChar);
			return Decode(bitsPerChar, decodeCallback, value, value.Length*bitsPerChar);
		}

		public static byte[] Decode(int bitsPerChar, DecodeCallback decodeCallback,
		                            IEnumerable<char> value, int bitsToDecode)
		{
			Helper.CheckRange("bitsPerChar", bitsPerChar, 1, 8);
			Helper.CheckNull("decodeCallback", decodeCallback);
			Helper.CheckNull("value", value);
			Helper.CheckRange("bitsToDecode", bitsToDecode, 0, int.MaxValue - 7);
			using (IEnumerator<char> e = value.GetEnumerator())
			{
				byte[] bytes = new byte[(bitsToDecode + 7)/8];

				int j = 0, bits = 0, buffer = 0;
				while (bitsToDecode > 0)
				{
					while (bits < 8)
					{
						if (!e.MoveNext())
						{
							break;
						}
						bits += bitsPerChar;
						buffer <<= bitsPerChar;
						buffer |= decodeCallback(e.Current) & ((1 << bitsPerChar) - 1);
					}

					int chunk = Math.Min(8, Math.Min(bits, bitsToDecode));
					bits -= chunk;
					bitsToDecode -= 8;

					int eightBit = buffer >> bits;
					buffer ^= eightBit << bits;
					bytes[j++] = (byte) (eightBit << (8 - chunk));
				}

				Debug.Assert(j == bytes.Length);
				return bytes;
			}
		}

		public static char[] Encode(int bitsPerChar, EncodeCallback encodeCallback,
		                            byte[] value)
		{
			Helper.CheckNull("value", value);
			Helper.CheckRange("value", value, 0, int.MaxValue/8);
			return Encode(bitsPerChar, encodeCallback, value, value.Length*8);
		}

		public static char[] Encode(int bitsPerChar, EncodeCallback encodeCallback,
		                            byte[] value, int bitsToEncode)
		{
			Helper.CheckRange("bitsPerChar", bitsPerChar, 1, 8);
			Helper.CheckNull("encodeCallback", encodeCallback);
			Helper.CheckNull("value", value);
			Helper.CheckRange("bitsToEncode", bitsToEncode, 0, int.MaxValue - (bitsPerChar - 1));
			char[] chars = new char[(bitsToEncode + bitsPerChar - 1)/bitsPerChar];

			int i = 0, j = 0, bits = 0, buffer = 0;
			while (bitsToEncode > 0)
			{
				if (bits < 6 && i < value.Length)
				{
					bits += 8;
					buffer <<= 8;
					buffer |= value[i++];
				}

				int chunk = Math.Min(bitsPerChar, Math.Min(bits, bitsToEncode));
				bits -= chunk;
				bitsToEncode -= bitsPerChar;

				int pow2Bits = buffer >> bits;
				buffer ^= pow2Bits << bits;
				chars[j++] = encodeCallback(pow2Bits << (bitsPerChar - chunk));
			}

			Debug.Assert(j == chars.Length);
			return chars;
		}
	}
}