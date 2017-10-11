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

// Ported this from Bruce Schneier's C implementation.
// Unlike Crypter, the BlowfishCipher class does NOT automatically
// add a null terminating last byte to the key. You have to do that
// yourself if your particular application requires it (Blowfish
// crypt does).

namespace CryptSharp.Utility
{
	using System;
	using System.Text;

	public partial class BlowfishCipher : IDisposable
	{
		private static readonly byte[] ZeroSalt = new byte[16];
		private static readonly uint[] Magic;
		private readonly uint[] P;
		private readonly uint[][] S;

		static BlowfishCipher()
		{
			byte[] magicBytes = Encoding.UTF8.GetBytes(BCryptMagic);
			Array.Resize(ref magicBytes, (magicBytes.Length + 7)/8*8);

			Magic = new uint[(magicBytes.Length + 3)/4];
			for (int i = 0; i < Magic.Length; i++)
			{
				Magic[i] = Helper.BytesToUInt32(magicBytes, i*4);
			}
		}

		private BlowfishCipher()
		{
			P = (uint[]) P0.Clone();
			S = new[] {(uint[]) S0[0].Clone(), (uint[]) S0[1].Clone(), (uint[]) S0[2].Clone(), (uint[]) S0[3].Clone()};
		}

		public static int BCryptLength
		{
			get { return Magic.Length*4 - 1; }
		}

		#region IDisposable Members

		public void Dispose()
		{
			Array.Clear(P, 0, P.Length);
			foreach (uint[] t in S)
			{
				Array.Clear(t, 0, t.Length);
			}
		}

		#endregion

		public static BlowfishCipher Create(byte[] key)
		{
			Helper.CheckRange("key", key, 4, 56);

			BlowfishCipher fish = new BlowfishCipher();
			fish.ExpandKey(key, ZeroSalt);
			return fish;
		}

		public static BlowfishCipher CreateEks(byte[] key, byte[] salt, int cost)
		{
			Helper.CheckRange("key", key, 1, 72);
			Helper.CheckRange("salt", salt, 16, 16);
			Helper.CheckRange("cost", cost, 4, 31);

			BlowfishCipher fish = new BlowfishCipher();
			fish.ExpandKey(key, salt);
			for (uint i = 1u << cost; i > 0; i --)
			{
				fish.ExpandKey(key, ZeroSalt);
				fish.ExpandKey(salt, ZeroSalt);
			}
			return fish;
		}

		public static byte[] BCrypt(byte[] key, byte[] salt, int cost)
		{
			using (BlowfishCipher fish = CreateEks(key, salt, cost))
			{
				return fish.BCrypt();
			}
		}

		public byte[] BCrypt()
		{
			uint[] magic = (uint[]) Magic.Clone();
			for (int j = 0; j < magic.Length; j += 2)
			{
				for (int i = 0; i < 64; i ++)
				{
					Encipher(ref magic[j], ref magic[j + 1]);
				}
			}

			byte[] magicBytes = new byte[magic.Length*4];
			for (int i = 0; i < magic.Length; i ++)
			{
				Helper.UInt32ToBytes(magic[i], magicBytes, i*4);
			}
			byte[] oldMagicBytes = magicBytes;
			Array.Resize(ref magicBytes, magicBytes.Length - 1);
			Array.Clear(oldMagicBytes, 0, oldMagicBytes.Length);
			return magicBytes;
		}

		private void ExpandKey(byte[] key, byte[] salt)
		{
			uint[] p = P;
			uint[][] s = S;
			int i, j, k;
			uint data, datal, datar;

			j = 0;
			for (i = 0; i < p.Length; i ++)
			{
				data = 0x00000000;
				for (k = 0; k < 4; k ++)
				{
					data = (data << 8) | key[j];
					if (++j >= key.Length)
					{
						j = 0;
					}
				}
				p[i] = p[i] ^ data;
			}

			uint saltL0 = Helper.BytesToUInt32(salt, 0);
			uint saltR0 = Helper.BytesToUInt32(salt, 4);
			uint saltL1 = Helper.BytesToUInt32(salt, 8);
			uint saltR1 = Helper.BytesToUInt32(salt, 12);

			datal = 0x00000000;
			datar = 0x00000000;

			for (i = 0; i < p.Length; i += 4)
			{
				datal ^= saltL0;
				datar ^= saltR0;
				Encipher(ref datal, ref datar);
				p[i + 0] = datal;
				p[i + 1] = datar;

				if (i + 2 == p.Length)
				{
					break;
				} // 18 here
				datal ^= saltL1;
				datar ^= saltR1;
				Encipher(ref datal, ref datar);
				p[i + 2] = datal;
				p[i + 3] = datar;
			}

			for (i = 0; i < s.Length; i ++)
			{
				uint[] sb = s[i];
				for (j = 0; j < sb.Length; j += 4)
				{
					datal ^= saltL1;
					datar ^= saltR1;
					Encipher(ref datal, ref datar);
					sb[j + 0] = datal;
					sb[j + 1] = datar;

					datal ^= saltL0;
					datar ^= saltR0;
					Encipher(ref datal, ref datar);
					sb[j + 2] = datal;
					sb[j + 3] = datar;
				}
			}
		}

		private uint F(uint x)
		{
			uint a, b, c, d;
			uint y;

			d = x & 0x00FF;
			x >>= 8;
			c = x & 0x00FF;
			x >>= 8;
			b = x & 0x00FF;
			x >>= 8;
			a = x & 0x00FF;
			y = S[0][a] + S[1][b];
			y = y ^ S[2][c];
			y = y + S[3][d];

			return y;
		}

		private static void CheckCipherBuffers
			(byte[] inputBuffer, int inputOffset,
			 byte[] outputBuffer, int outputOffset)
		{
			Helper.CheckBounds("inputBuffer", inputBuffer, inputOffset, 8);
			Helper.CheckBounds("outputBuffer", outputBuffer, outputOffset, 8);
		}

		public void Encipher(byte[] buffer, int offset)
		{
			Encipher(buffer, offset, buffer, offset);
		}

		public void Encipher
			(byte[] inputBuffer, int inputOffset,
			 byte[] outputBuffer, int outputOffset)
		{
			CheckCipherBuffers(inputBuffer, inputOffset, outputBuffer, outputOffset);
			uint xl = Helper.BytesToUInt32(inputBuffer, inputOffset + 0);
			uint xr = Helper.BytesToUInt32(inputBuffer, inputOffset + 4);
			Encipher(ref xl, ref xr);
			Helper.UInt32ToBytes(xl, outputBuffer, outputOffset + 0);
			Helper.UInt32ToBytes(xr, outputBuffer, outputOffset + 4);
		}

		public void Encipher(ref uint xl, ref uint xr)
		{
			uint Xl, Xr, temp;
			int i;

			Xl = xl;
			Xr = xr;

			for (i = 0; i < N; i ++)
			{
				Xl = Xl ^ P[i];
				Xr = F(Xl) ^ Xr;

				temp = Xl;
				Xl = Xr;
				Xr = temp;
			}

			temp = Xl;
			Xl = Xr;
			Xr = temp;

			Xr = Xr ^ P[N];
			Xl = Xl ^ P[N + 1];

			xl = Xl;
			xr = Xr;
		}

		public void Decipher(byte[] buffer, int offset)
		{
			Decipher(buffer, offset, buffer, offset);
		}

		public void Decipher
			(byte[] inputBuffer, int inputOffset,
			 byte[] outputBuffer, int outputOffset)
		{
			CheckCipherBuffers(inputBuffer, inputOffset, outputBuffer, outputOffset);
			uint xl = Helper.BytesToUInt32(inputBuffer, inputOffset + 0);
			uint xr = Helper.BytesToUInt32(inputBuffer, inputOffset + 4);
			Decipher(ref xl, ref xr);
			Helper.UInt32ToBytes(xl, outputBuffer, outputOffset + 0);
			Helper.UInt32ToBytes(xr, outputBuffer, outputOffset + 4);
		}

		public void Decipher(ref uint xl, ref uint xr)
		{
			uint Xl, Xr, temp;
			int i;

			Xl = xl;
			Xr = xr;

			for (i = N + 1; i > 1; i --)
			{
				Xl = Xl ^ P[i];
				Xr = F(Xl) ^ Xr;

				temp = Xl;
				Xl = Xr;
				Xr = temp;
			}

			temp = Xl;
			Xl = Xr;
			Xr = temp;

			Xr = Xr ^ P[1];
			Xl = Xl ^ P[0];

			xl = Xl;
			xr = Xr;
		}
	}
}