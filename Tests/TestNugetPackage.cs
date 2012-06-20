namespace CryptTest
{
	using System.Collections.Generic;
	using System.IO;
	using System.Reflection;
	using System.Security.Cryptography;
	using System.Text;
	using System.Text.RegularExpressions;
	using CryptSharp;
	using CryptSharp.Utility;
	using NUnit.Framework;

	[TestFixture]
	public class TestNugetPackage
	{
		
		[Test(Description = "BCrypt Tests")]
		public void TestBCrypt()
		{
			var vectors = Assembly.GetExecutingAssembly().GetManifestResourceStream("CryptTest.vectors.BCrypt.txt");

			using (var stream = vectors)
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
						Assert.AreEqual(crypt, testCrypt, string.Format("WARNING: Crypt failed ({0} instead of {1})", testCrypt, crypt));
					}
				}
			}
		}

		[Test(Description = "Blowfish Tests")]
		public void TestBlowfish()
		{
			var vectors = Assembly.GetExecutingAssembly().GetManifestResourceStream("CryptTest.vectors.Blowfish.txt");

			using (Stream stream = vectors)
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

						using (BlowfishCipher fish = BlowfishCipher.Create(keyBytes))
						{
							var testCipherBytes = new byte[8];
							fish.Encipher(clearBytes, 0, testCipherBytes, 0);
							var testCipher = new string(HexBase16.Encode(testCipherBytes));

							Assert.AreEqual(cipher, testCipher, string.Format("Encipher failed test ({0} became {1})", cipher, testCipher));

							var testClearBytes = new byte[8];
							fish.Decipher(testCipherBytes, 0, testClearBytes, 0);
							var testClear = new string(HexBase16.Encode(testClearBytes));


							Assert.AreEqual(clear, testClear, string.Format("Decipher failed ({0} became {1})", clear, testClear));
						}
					}
				}
			}
		}

		[Test(Description = "PBKDF2 Tests")]
		public void TestPBKDF2()
		{
			var pbkdfVectors = new List<Vector>
			                   	{
			                   		new Vector
			                   			{
			                   				Password = "password", Salt = "salt", C = 1, Len = 20,
			                   				Expected = @"0c 60 c8 0f 96 1f 0e 71
														f3 a9 b5 24 af 60 12 06
														2f e0 37 a6"
			                   			}, new Vector
			                   			   	{
			                   			   		Password = "password", Salt = "salt", C = 4096, Len = 20,
			                   			   		Expected = @"4b 00 79 01 b7 65 48 9a
															be ad 49 d9 26 f7 21 d0
															65 a4 29 c1"
			                   			   	}, new Vector
			                   			   	   	{
			                   			   	   		Password = "passwordPASSWORDpassword", Salt = "saltSALTsaltSALTsaltSALTsaltSALTsalt", C = 4096, Len = 25,
			                   			   	   		Expected = @"3d 2e ec 4f e4 1c 84 9b
																80 c8 d8 36 62 c0 e4 4a
																8b 29 1a 96 4c f2 f0 70
																38"
			                   			   	   	}, new Vector
			                   			   	   	   	{
			                   			   	   	   		Password = "pass\0word", Salt = "sa\0lt", C = 4096, Len = 16,
			                   			   	   	   		Expected = @"56 fa 6a a7 55 48 09 9d
																	 cc 37 d7 f0 34 25 e0 c3"
			                   			   	   	   	}
			                   	};

			foreach (var vec in pbkdfVectors)
			{
				Assert.AreEqual(vec.TestSHA1(), vec.Expected.Clean());
			}
		}

		[Test(Description = "SCrypt Tests")]
		public void TestSCrypt()
		{
			var sCryptVectors = new List<Vector>
			              	{
			              		new Vector
			              			{
			              				Password = "", Salt = "", N = 16, R = 1, P = 1, Len = 64,
			              				Expected = @"77 d6 57 62 38 65 7b 20 3b 19 ca 42 c1 8a 04 97
											f1 6b 48 44 e3 07 4a e8 df df fa 3f ed e2 14 42
											fc d0 06 9d ed 09 48 f8 32 6a 75 3a 0f c8 1f 17
											e8 d3 e0 fb 2e 0d 36 28 cf 35 e2 0c 38 d1 89 06"
			              			},
			              		new Vector
			              			{
			              				Password = "password", Salt = "NaCl", N = 1024, R = 8, P = 16, Len = 64,
			              				Expected = @"fd ba be 1c 9d 34 72 00 78 56 e7 19 0d 01 e9 fe
											7c 6a d7 cb c8 23 78 30 e7 73 76 63 4b 37 31 62
											2e af 30 d9 2e 22 a3 88 6f f1 09 27 9d 98 30 da
											c7 27 af b9 4a 83 ee 6d 83 60 cb df a2 cc 06 40"
			              			},
								new Vector
			              			{
			              				Password = "pleaseletmein", Salt = "SodiumChloride", N = 16384, R = 8, P = 1, Len = 64,
			              				Expected = @"70 23 bd cb 3a fd 73 48 46 1c 06 cd 81 fd 38 eb
										fd a8 fb ba 90 4f 8e 3e a9 b5 43 f6 54 5d a1 f2
										d5 43 29 55 61 3f 0f cf 62 d4 97 05 24 2a 9a f9
										e6 1e 85 dc 0d 65 1e 40 df cf 01 7b 45 57 58 87"
			              			}
			              	};

			foreach (var vec in sCryptVectors)
			{
				Assert.AreEqual(vec.TestSCrypt(), vec.Expected.Clean());
			}
		}
	}


	public class Vector
	{
		public string Password { get; set; }
		public string Salt { get; set; }
		public int C { get; set; }
		public int N { get; set; }
		public int R { get; set; }
		public int P { get; set; }
		public int Len { get; set; }
		public string Expected { get; set; }
	}

	public static class Helper
	{
		public static string Clean(this string st)
		{
			return st.Replace(" ", "")
				.Replace("\r", "")
				.Replace("\n", "")
				.Replace("\t", "")
				.ToUpper();
		}

		public static string TestSHA1(this Vector vector)
		{
			var derivedBytes = new byte[vector.Len];
			Pbkdf2.ComputeKey
				(Encoding.ASCII.GetBytes(vector.Password), Encoding.ASCII.GetBytes(vector.Salt),
				 vector.C, Pbkdf2.CallbackFromHmac<HMACSHA1>(), 20, derivedBytes);

			var derived = new string(HexBase16.Encode(derivedBytes));

			return derived;
		}

		public static string TestSCrypt(this Vector vector)
		{
			var derivedBytes = new byte[vector.Len];
			SCrypt.ComputeKey
				(Encoding.ASCII.GetBytes(vector.Password), Encoding.ASCII.GetBytes(vector.Salt),
				 vector.N, vector.R, vector.P, null, derivedBytes);

			var derived = new string(HexBase16.Encode(derivedBytes));

			return derived;
		}
	}
}