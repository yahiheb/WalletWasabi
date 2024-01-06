namespace WalletWasabi.Blockchain.BlockFilters;
internal static class ByteArrayExtensions
{
	internal static byte[] SafeSubarray(this byte[] array, int offset, int count)
	{
		ArgumentNullException.ThrowIfNull(array);

		if (offset < 0 || offset > array.Length)
		{
			throw new ArgumentOutOfRangeException(nameof(offset));
		}

		if (count < 0 || offset + count > array.Length)
		{
			throw new ArgumentOutOfRangeException(nameof(count));
		}

		if (offset == 0 && array.Length == count)
		{
			return array;
		}

		var data = new byte[count];
		Buffer.BlockCopy(array, offset, data, 0, count);
		return data;
	}

	internal static byte[] SafeSubarray(this byte[] array, int offset)
	{
		ArgumentNullException.ThrowIfNull(array);

		if (offset < 0 || offset > array.Length)
		{
			throw new ArgumentOutOfRangeException(nameof(offset));
		}

		var count = array.Length - offset;
		var data = new byte[count];
		Buffer.BlockCopy(array, offset, data, 0, count);
		return data;
	}
}
