using System.Collections.Immutable;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using ExchangeRateProviderInfo = (string Name, string ApiUrl, System.Func<string, decimal> Extractor);

namespace WalletWasabi.Wallets.Exchange;

public class ExchangeRateProvider(IHttpClientFactory httpClientFactory)
{
	public static readonly ImmutableArray<ExchangeRateProviderInfo> Providers =
	[
		("mempoolspace", "https://mempool.space/api/v1/prices", JsonPath(".USD")),
		("blockchaininfo", "https://blockchain.info/ticker", JsonPath(".USD.buy")),
		("coingecko", "https://api.coingecko.com/api/v3/coins/markets?vs_currency=usd&ids=bitcoin", JsonPath(".[0].current_price")),
		("gemini", "https://api.gemini.com/v1/pubticker/btcusd", JsonPath(".bid"))
	];

	public async Task<ExchangeRate> GetExchangeRateAsync(string providerName, string userAgent, CancellationToken cancellationToken)
	{
		var providerInfo = Providers.FirstOrDefault(x => x.Name.Equals(providerName, StringComparison.InvariantCultureIgnoreCase));
		if (providerInfo == default)
		{
			throw new NotSupportedException($"Exchange rate provider '{providerName}' is not supported.");
		}
		var url = new Uri(providerInfo.ApiUrl);

		var httpClient = httpClientFactory.CreateClient($"{providerName}-exchange-rate-provider");
		httpClient.BaseAddress = new Uri($"{url.Scheme}://{url.Host}");
		httpClient.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", userAgent);

		using var response = await httpClient.GetAsync(url.PathAndQuery, cancellationToken).ConfigureAwait(false);
		var json = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
		var rate = providerInfo.Extractor(json);
		return new ExchangeRate("USD", rate);
	}

	private static Func<string, decimal> JsonPath(string xpath) =>
		json =>
			JToken.Parse(json).SelectToken(xpath)?.Value<decimal>()
			?? throw new ArgumentException($@"The xpath {xpath} was not found.", nameof(xpath));
}