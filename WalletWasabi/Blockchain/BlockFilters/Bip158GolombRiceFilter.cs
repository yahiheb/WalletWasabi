using System;
using System.Collections.Generic;
using System.Linq;
using NBitcoin;
using NBitcoin.Crypto;
using NBitcoin.Protocol;

namespace WalletWasabi.Blockchain.BlockFilters;

/// <summary>
/// Implements a Golomb-coded set to be use in the creation of client-side filter
/// for a new kind Bitcoin light clients. This code is based on the BIP:
/// https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki
/// </summary>
public class Bip158GolombRiceFilter
{
	// This is the value used by default as P as defined in the BIP.
	internal const byte DefaultP = 19;

	internal const uint DefaultM = 784_931;

	/// <summary>
	/// a value which is computed as 1/fp where fp is the desired false positive rate.
	/// </summary>
	public byte P { get; }

	/// <summary>
	/// a value which is computed as N * fp (or false positive rate = 1/M).
	/// this value allows filter to uniquely tune the range that items are hashed onto
	/// before compressing
	/// </summary>
	public uint M { get; }

	/// <summary>
	/// Number of elements in the filter
	/// </summary>
	public int N { get; }

	/// <summary>
	/// Raw filter data
	/// </summary>
	public byte[] Data { get; }

	private ulong ModulusP { get; }
	private ulong ModulusNP { get; }

	public static Bip158GolombRiceFilter Empty { get; } = new Bip158GolombRiceFilter(new byte[] { 0 });

	/// <summary>
	/// Creates a new Golomb-Rice filter from the data byte array which
	/// contains a serialized filter. Uses the DefaultP value (20).
	/// </summary>
	public static Bip158GolombRiceFilter Parse(string str)
	{
		var bytes = NBitcoin.DataEncoders.Encoders.Hex.DecodeData(str);
		return new Bip158GolombRiceFilter(bytes);
	}

	/// <summary>
	/// Creates a new Golomb-Rice filter from the data byte array which
	/// contains a serialized filter. Uses the DefaultP value (20).
	/// </summary>
	/// <param name="data">A serialized Golomb-Rice filter.</param>
	public Bip158GolombRiceFilter(byte[] data)
		: this(data, DefaultP, DefaultM)
	{
	}

	/// <summary>
	/// Creates a new Golomb-Rice filter from the data byte array which
	/// contains a serialized filter.
	/// </summary>
	/// <param name="data">A serialized Golomb-Rice filter.</param>
	/// <param name="p">The P value to use.</param>
	/// <param name="m">The M value to use.</param>
	public Bip158GolombRiceFilter(byte[] data, byte p, uint m)
	{
		P = p;
		M = m;
		var n = new VarInt();
		var stream = new BitcoinStream(data);
		stream.ReadWrite(ref n);
		N = (int)n.ToLong();
		var l = n.ToBytes().Length;
		Data = data.SafeSubarray(l);
	}

	/// <summary>
	/// Creates a new Golomb-Rice filter from the data byte array.
	/// </summary>
	/// <param name="data">A serialized Golomb-Rice filter.</param>
	/// <param name="n">The number of elements in the filter.</param>
	/// <param name="p">The P value to use.</param>
	/// <param name="m">The M value to use.</param>
	internal Bip158GolombRiceFilter(byte[] data, int n, byte p, uint m)
	{
		P = p;
		N = n;
		M = m;

		ModulusP = 1UL << P;
		ModulusNP = (ulong)N * M;
		Data = data;
	}

	/// <summary>
	/// Computes the sorted-and-uncompressed list of values to be included in the filter.
	/// /// </summary>
	/// <param name="p">p value used.</param>
	/// <param name="key">Key used for hashing the data elements.</param>
	/// <param name="data">Data elements to be computed in the list.</param>
	/// <returns></returns>
	internal static ulong[] ConstructHashedSet(byte p, int n, uint m, byte[] key, IEnumerable<byte[]> data, int dataCount)
	{
		// N the number of items to be inserted into the set.
		// The list of data item hashes.
		var values = new ulong[dataCount];
		var valuesIndex = 0;
		var modP = 1UL << p;
		var modNP = ((ulong)n) * m;
		var nphi = modNP >> 32;
		var nplo = (ulong)(uint)modNP;

		var k0 = BitConverter.ToUInt64(key, 0);
		var k1 = BitConverter.ToUInt64(key, 8);

		// Process the data items and calculate the 64 bits hash for each of them.
		foreach (var item in data)
		{
			var hash = SipHash(k0, k1, item);
			var value = FastReduction(hash, nphi, nplo);
			values[valuesIndex++] = value;
		}

		Array.Sort(values);
		return values;
	}

	/// <summary>
	/// Calculates the filter's header.
	/// </summary>
	/// <param name="previousHeader">Previous filter header.</param>
	/// <returns>The filter header.</returns>
	public uint256 GetHeader(uint256 previousHeader)
	{
		var curFilterHashBytes = Hashes.DoubleSHA256(ToBytes()).ToBytes();
		var prvFilterHashBytes = previousHeader.ToBytes();
		return Hashes.DoubleSHA256((byte[])curFilterHashBytes.Concat(prvFilterHashBytes));
	}

	/// <summary>
	/// Checks if the value passed is in the filter.
	/// </summary>
	/// <param name="data">Data element to check in the filter.</param>
	/// <param name="key">Key used for hashing the data elements.</param>
	/// <returns>true if the element is in the filter, otherwise false.</returns>
	public bool Match(byte[] data, byte[] key)
	{
		var reader = new GRCodedStreamReader(new BitStream(Data), P, 0);
		return Match(data, key, reader);
	}

	/// <summary>
	/// Checks if the value passed is in the filter.
	/// </summary>
	/// <param name="data">Data element to check in the filter.</param>
	/// <param name="key">Key used for hashing the data elements.</param>
	/// <param name="reader">Golomb-Rice stream reader.</param>
	/// <returns>true if the element is in the filter, otherwise false.</returns>
	public bool Match(byte[] data, byte[] key, GRCodedStreamReader reader)
	{
		ArgumentNullException.ThrowIfNull(data);

		return MatchAny(new[] { data }, 1, key, reader);
	}

	/// <summary>
	/// Checks if any of the provided elements is in the filter.
	/// </summary>
	/// <param name="data">Data elements to check in the filter.</param>
	/// <param name="key">Key used for hashing the data elements.</param>
	/// <returns>true if at least one of the elements is in the filter, otherwise false.</returns>
	public bool MatchAny(byte[][] data, byte[] key)
	{
		var reader = new GRCodedStreamReader(new BitStream(Data), P, 0);
		return MatchAny(data, data.Length, key, reader);
	}

	/// <summary>
	/// Checks if any of the provided elements is in the filter.
	/// </summary>
	/// <param name="data">Data elements to check in the filter.</param>
	/// <param name="key">Key used for hashing the data elements.</param>
	/// <returns>true if at least one of the elements is in the filter, otherwise false.</returns>
	public bool MatchAny(IEnumerable<byte[]> data, byte[] key)
	{
		var reader = new GRCodedStreamReader(new BitStream(Data), P, 0);
		return MatchAny(data, key, reader);
	}

	/// <summary>
	/// Checks if any of the provided elements is in the filter.
	/// </summary>
	/// <param name="data">Data elements to check in the filter.</param>
	/// <param name="key">Key used for hashing the data elements.</param>
	/// <param name="reader">Golomb-Rice stream reader.</param>
	/// <returns>true if at least one of the elements is in the filter, otherwise false.</returns>
	public bool MatchAny(IEnumerable<byte[]> data, byte[] key, GRCodedStreamReader reader)
	{
		ArgumentNullException.ThrowIfNull(data);

		if (data is byte[][] dataArray)
		{
			return MatchAny(dataArray, dataArray.Length, key, reader);
		}
		else if (data is ICollection<byte[]> dataCollection)
		{
			return MatchAny(dataCollection, dataCollection.Count, key, reader);
		}
		else
		{
			return MatchAny(data, data.Count(), key, reader);
		}
	}

	/// <summary>
	/// Checks if any of the provided elements is in the filter.
	/// </summary>
	/// <param name="data">Data elements to check in the filter.</param>
	/// <param name="key">Key used for hashing the data elements.</param>
	/// <returns>true if at least one of the elements is in the filter, otherwise false.</returns>
	internal bool MatchAny(IEnumerable<byte[]> data, int dataCount, byte[] key, GRCodedStreamReader reader)
	{
		try
		{
			return InternalMatchAny(data, dataCount, key, reader);
		}
		finally
		{
			reader.ResetPosition();
		}
	}

	private bool InternalMatchAny(IEnumerable<byte[]> data, int dataCount, byte[] key, GRCodedStreamReader sr)
	{
		if (data == null || dataCount == 0)
		{
			throw new ArgumentException("data can not be null or empty array.", nameof(data));
		}

		ArgumentNullException.ThrowIfNull(key);

		var hs = ConstructHashedSet(P, N, M, key, data, dataCount);

		while (sr.TryRead(out var val))
		{
			var dataIndex = 0;
			while (true)
			{
				if (dataIndex == dataCount)
				{
					return false;
				}

				if (hs[dataIndex] == val)
				{
					return true;
				}

				if (hs[dataIndex] > val)
				{
					break;
				}

				dataIndex++;
			}
		}

		return false;
	}

	/// <summary>
	/// Serialize the filter as a array of bytes using [varint(N) | data].
	/// </summary>
	/// <returns>A array of bytes with the serialized filter data.</returns>
	public byte[] ToBytes()
	{
		var n = new VarInt((ulong)N).ToBytes();
		return (byte[])n.Concat(Data);
	}

	/// <summary>
	/// Serialize the filter as hexadecimal string.
	/// </summary>
	/// <returns>A string with the serialized filter data</returns>
	public override string ToString()
	{
		return NBitcoin.DataEncoders.Encoders.Hex.EncodeData(ToBytes());
	}

	/// <summary>
	/// Create a cached Golomb-Rice stream reader.
	/// </summary>
	/// <returns>A new cached Golomb-Rice stream reader instance</returns>
	public CachedGRCodedStreamReader GetNewGRStreamReader()
	{
		return new CachedGRCodedStreamReader(new BitStream(Data), P, 0);
	}

	internal static ulong FastReduction(ulong value, ulong nhi, ulong nlo)
	{
		// First, we'll spit the item we need to reduce into its higher and lower bits.
		var vhi = value >> 32;
		var vlo = (ulong)(uint)value;

		// Then, we distribute multiplication over each part.
		var vnphi = vhi * nhi;
		var vnpmid = vhi * nlo;
		var npvmid = nhi * vlo;
		var vnplo = vlo * nlo;

		// We calculate the carry bit.
		var carry = ((uint)vnpmid + (ulong)(uint)npvmid + (vnplo >> 32)) >> 32;

		// Last, we add the high bits, the middle bits, and the carry.
		value = vnphi + (vnpmid >> 32) + (npvmid >> 32) + carry;

		return value;
	}

	private static ulong SipHash(ulong k0, ulong k1, byte[] data)
	{
		var hasher = new Hashes.SipHasher(k0, k1);
		hasher.Write(data);
		return hasher.Finalize();
	}
}
