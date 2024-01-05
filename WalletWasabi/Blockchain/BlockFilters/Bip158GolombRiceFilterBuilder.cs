using System.Collections.Generic;
using System.IO;
using NBitcoin;

namespace WalletWasabi.Blockchain.BlockFilters;

/// <summary>
/// Class for creating Golomb-Rice filters for a given block.
/// It provides methods for building two kind of filters out-of-the-box:
/// Basic Filters and Extenden Filters.
/// </summary>
public class Bip158GolombRiceFilterBuilder
{
	private byte _p = Bip158GolombRiceFilter.DefaultP;
	private uint _m = Bip158GolombRiceFilter.DefaultM;
	private byte[] _key;
	private HashSet<byte[]> _values;

	/// <summary>
	/// Helper class for making sure not two identical data elements are
	/// included in a filter.
	/// </summary>
	private class ByteArrayComparer : IEqualityComparer<byte[]>
	{
		public static readonly ByteArrayComparer Instance = new();

		private ByteArrayComparer()
		{
		}

		public bool Equals(byte[] a, byte[] b)
		{
			if (a.Length != b.Length)
			{
				return false;
			}

			for (int i = 0; i < a.Length; i++)
			{
				if (a[i] != b[i])
				{
					return false;
				}
			}

			return true;
		}

		public int GetHashCode(byte[] a)
		{
			uint b = 0;
			for (int i = 0; i < a.Length; i++)
			{
				b = ((b << 23) | (b >> 9)) ^ a[i];
			}

			return unchecked((int)b);
		}
	}

	/// <summary>
	/// Builds the basic filter for a given block.
	///
	/// The basic filter is designed to contain everything that a light client needs to sync a regular Bitcoin wallet.
	/// A basic filter MUST contain exactly the following items for each transaction in a block:
	///  * The outpoint of each input, except for the coinbase transaction
	///  * The scriptPubKey of each output
	///  * The txid of the transaction itself
	/// </summary>
	/// <param name="block">The block used for building the filter.</param>
	/// <returns>The basic filter for the block.</returns>
	public static Bip158GolombRiceFilter BuildBasicFilter(Block block)
	{
		var builder = new Bip158GolombRiceFilterBuilder()
			.SetKey(block.GetHash());

		foreach (var tx in block.Transactions)
		{
			if (!tx.IsCoinBase) // except for the coinbase transaction
			{
				foreach (var txin in tx.Inputs)
				{
					// The outpoint of each input
					builder.AddOutPoint(txin.PrevOut);
				}
			}

			foreach (var txout in tx.Outputs)
			{
				// The scriptPubKey of each output
				builder.AddScriptPubkey(txout.ScriptPubKey);
			}
		}

		return builder.Build();
	}

	/// <summary>
	/// Creates a new Golob-Rice filter builder.
	/// </summary>
	public Bip158GolombRiceFilterBuilder()
	{
		_values = new HashSet<byte[]>(ByteArrayComparer.Instance);
	}

	/// <summary>
	/// Sets the key used for hashing the filter data elements.
	/// The first half of the block hash is used as described in the BIP.
	/// </summary>
	/// <param name="blockHash">The block hash which the hashing key is derived from.</param>
	/// <returns>The updated filter builder instance</returns>
	public Bip158GolombRiceFilterBuilder SetKey(uint256 blockHash)
	{
		ArgumentNullException.ThrowIfNull(blockHash);

		_key = blockHash.ToBytes().SafeSubarray(0, 16);
		return this;
	}

	/// <summary>
	/// Sets the P value to use.
	/// </summary>
	/// <param name="p">P value</param>
	/// <returns>The updated filter builder instance.</returns>
	public Bip158GolombRiceFilterBuilder SetP(int p)
	{
		if (p <= 0 || p > 32)
		{
			throw new ArgumentOutOfRangeException(nameof(p), "value has to be greater than zero and less or equal to 32.");
		}

		_p = (byte)p;
		return this;
	}

	/// <summary>
	/// Sets the M value to use.
	/// </summary>
	/// <param name="m">M value</param>
	/// <returns>The updated filter builder instance.</returns>
	public Bip158GolombRiceFilterBuilder SetM(uint m)
	{
		_m = m;
		return this;
	}

	/// <summary>
	/// Adds a transacion id to the list of elements that will be used for building the filter.
	/// </summary>
	/// <param name="id">The transaction id.</param>
	/// <returns>The updated filter builder instance.</returns>
	public Bip158GolombRiceFilterBuilder AddTxId(uint256 id)
	{
		ArgumentNullException.ThrowIfNull(id);

		_values.Add(id.ToBytes());
		return this;
	}

	/// <summary>
	/// Adds a scriptPubKey to the list of elements that will be used for building the filter.
	/// </summary>
	/// <param name="scriptPubkey">The scriptPubkey.</param>
	/// <returns>The updated filter builder instance.</returns>
	public Bip158GolombRiceFilterBuilder AddScriptPubkey(Script scriptPubkey)
	{
		ArgumentNullException.ThrowIfNull(scriptPubkey);

		// Unsafe is OK because Script is readonly and we do not modify the arrays inside values
		_values.Add(scriptPubkey.ToBytes(true));
		return this;
	}

	/// <summary>
	/// Adds a scriptSig to the list of elements that will be used for building the filter.
	/// </summary>
	/// <param name="scriptSig">The scriptSig.</param>
	/// <returns>The updated filter builder instance.</returns>
	public Bip158GolombRiceFilterBuilder AddScriptSig(Script scriptSig)
	{
		ArgumentNullException.ThrowIfNull(scriptSig);

		var data = new List<byte[]>();
		foreach (var op in scriptSig.ToOps())
		{
			if (op.PushData != null)
			{
				data.Add(op.PushData);
			}
			else if (op.Code == OpcodeType.OP_0)
			{
				data.Add(EmptyBytes);
			}
		}
		AddEntries(data);
		return this;
	}

	private static readonly byte[] EmptyBytes = Array.Empty<byte>();

	/// <summary>
	/// Adds a witness stack to the list of elements that will be used for building the filter.
	/// </summary>
	/// <param name="witScript">The witScript.</param>
	/// <returns>The updated filter builder instance.</returns>
	public void AddWitness(WitScript witScript)
	{
		ArgumentNullException.ThrowIfNull(witScript);

		AddEntries(witScript.Pushes);
	}

	/// <summary>
	/// Adds an outpoint to the list of elements that will be used for building the filter.
	/// </summary>
	/// <param name="outpoint">The outpoint.</param>
	/// <returns>The updated filter builder instance.</returns>
	public Bip158GolombRiceFilterBuilder AddOutPoint(OutPoint outpoint)
	{
		ArgumentNullException.ThrowIfNull(outpoint);

		MemoryStream ms = new(32 + 4);
		outpoint.ReadWrite(new BitcoinStream(ms, true));
		_values.Add(ms.ToArrayEfficient());
		return this;
	}

	/// <summary>
	/// Adds a list of elements to the list of elements that will be used for building the filter.
	/// </summary>
	/// <param name="entries">The entries.</param>
	/// <returns>The updated filter builder instance.</returns>
	public Bip158GolombRiceFilterBuilder AddEntries(IEnumerable<byte[]> entries)
	{
		ArgumentNullException.ThrowIfNull(entries);

		foreach (var entry in entries)
		{
			_values.Add(entry);
		}
		return this;
	}

	/// <summary>
	/// Builds the Golomb-Rice filters from the parameters and data elements included.
	/// </summary>
	/// <returns>The built filter.</returns>
	public Bip158GolombRiceFilter Build()
	{
		var n = _values.Count;
		var hs = Bip158GolombRiceFilter.ConstructHashedSet(_p, n, _m, _key, _values, _values.Count);
		var filterData = Compress(hs, _p);

		return new Bip158GolombRiceFilter(filterData, n, _p, _m);
	}

	private static byte[] Compress(ulong[] values, byte p)
	{
		var bitStream = new BitStream();
		var sw = new GRCodedStreamWriter(bitStream, p);

		foreach (var value in values)
		{
			sw.Write(value);
		}
		return bitStream.ToByteArray();
	}
}
