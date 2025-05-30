namespace WalletWasabi.Backend.Models.Responses;

public class VersionsResponse
{
	public required string ClientVersion { get; init; }

	public required string BackendMajorVersion { get; init; }

	public required string CommitHash { get; init; }
}
