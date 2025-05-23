using System.Collections.Generic;
using System.Linq;
using System.Threading.Channels;
using NBitcoin;
using WalletWasabi.Logging;
using WalletWasabi.WabiSabi.Coordinator.Rounds;

namespace WalletWasabi.WabiSabi.Coordinator.DoSPrevention;

public class Prison
{
	public Prison(IEnumerable<Offender> offenders, ChannelWriter<Offender> channelWriterWriter)
	{
		_offendersByTxId = offenders.GroupBy(x => x.OutPoint.Hash).ToDictionary(x => x.Key, x => x.ToList());
		_notificationChannelWriter = channelWriterWriter;
	}

	private readonly ChannelWriter<Offender> _notificationChannelWriter;
	private readonly Dictionary<uint256, List<Offender>> _offendersByTxId;
	private readonly Dictionary<OutPoint, TimeFrame> _banningTimeCache = new();

	/// <remarks>_lock object to guard <see cref="_offendersByTxId"/>and <see cref="_banningTimeCache"/></remarks>
	private readonly object _lock = new();

	public void CoordinatorStabilitySafetyBan(OutPoint outPoint, uint256 roundId) =>
		Punish(new Offender(outPoint, DateTimeOffset.UtcNow, new CoordinatorStabilitySafety(roundId)));

	public void FailedToConfirm(OutPoint outPoint, Money value, uint256 roundId) =>
		Punish(new Offender(outPoint, DateTimeOffset.UtcNow, new RoundDisruption(roundId, value, RoundDisruptionMethod.DidNotConfirm)));

	public void FailedToSign(OutPoint outPoint, Money value, uint256 roundId) =>
		Punish(new Offender(outPoint, DateTimeOffset.UtcNow, new RoundDisruption(roundId, value, RoundDisruptionMethod.DidNotSign)));

	public void FailedVerification(OutPoint outPoint, uint256 roundId) =>
		Punish(new Offender(outPoint, DateTimeOffset.UtcNow, new FailedToVerify(roundId)));

	public void CheatingDetected(OutPoint outPoint, uint256 roundId) =>
		Punish(new Offender(outPoint, DateTimeOffset.UtcNow, new Cheating(roundId)));

	public void DoubleSpent(OutPoint outPoint, Money value, uint256 roundId) =>
		Punish(new Offender(outPoint, DateTimeOffset.UtcNow, new RoundDisruption(roundId, value, RoundDisruptionMethod.DoubleSpent)));

	public void InheritPunishment(OutPoint outpoint, OutPoint[] ancestors) =>
		Punish(new Offender(outpoint, DateTimeOffset.UtcNow, new Inherited(ancestors)));

	public void FailedToSignalReadyToSign(OutPoint outPoint, Money value, uint256 roundId) =>
		Punish(new Offender(outPoint, DateTimeOffset.UtcNow, new RoundDisruption(roundId, value, RoundDisruptionMethod.DidNotSignalReadyToSign)));

	public bool IsBanned(OutPoint outpoint, DoSConfiguration configuration, DateTimeOffset when) =>
		GetBanTimePeriod(outpoint, configuration).Includes(when);

	public TimeFrame GetBanTimePeriod(OutPoint outpoint, DoSConfiguration configuration)
	{
		TimeFrame EffectiveMinTimeFrame(TimeFrame banningPeriod) =>
			banningPeriod.Duration < configuration.MinTimeInPrison
				? TimeFrame.Zero
				: banningPeriod;

		TimeSpan CalculatePunishment(Offender offender, RoundDisruption disruption)
		{
			var basePunishmentInHours = configuration.SeverityInBitcoinsPerHour / disruption.Value.ToDecimal(MoneyUnit.BTC);

			IReadOnlyList<RoundDisruption> offenderHistory;
			lock (_lock)
			{
				offenderHistory = _offendersByTxId.TryGetValue(offender.OutPoint.Hash, out var offenders)
					? offenders
						.Where(x => x.OutPoint.N == offender.OutPoint.N)
						.Select(x => x.Offense)
						.OfType<RoundDisruption>()
						.ToList()
					: Array.Empty<RoundDisruption>();
			}

			var maxOffense = offenderHistory.Count == 0
				? 1
				: offenderHistory.Max( x => x switch {
					{ Method: RoundDisruptionMethod.DidNotConfirm } => configuration.PenaltyFactorForDisruptingConfirmation,
					{ Method: RoundDisruptionMethod.DidNotSign } => configuration.PenaltyFactorForDisruptingSigning,
					{ Method: RoundDisruptionMethod.DoubleSpent } => configuration.PenaltyFactorForDisruptingByDoubleSpending,
					{ Method: RoundDisruptionMethod.DidNotSignalReadyToSign } => configuration.PenaltyFactorForDisruptingSignalReadyToSign,

					_ => throw new NotSupportedException("Unknown round disruption method.")
				});

			var repetitions = offenderHistory.Count;
			var repetitionFactor = Math.Pow(1.3, repetitions - 1); // Exponential punishment

			var prisonTime = basePunishmentInHours * maxOffense * (decimal)repetitionFactor;
			return TimeSpan.FromHours((double)prisonTime);
		}

		TimeFrame CalculatePunishmentInheritance(OutPoint[] ancestors)
		{
			var banningTimeFrame = ancestors
				.Select(a => (Ancestor: a, BanningTime: GetBanTimePeriod(a, configuration)))
				.MaxBy(x => x.BanningTime.EndTime)
				.BanningTime;
			return new TimeFrame(banningTimeFrame.StartTime, banningTimeFrame.Duration / 2);
		}

		Offender? offender;
		lock (_lock)
		{
			if (_banningTimeCache.TryGetValue(outpoint, out var cachedBanningTime))
			{
				return cachedBanningTime;
			}

			offender = _offendersByTxId.TryGetValue(outpoint.Hash, out var offenders)
				? offenders.LastOrDefault(x => x.OutPoint == outpoint)
				: null;
		}

		var banningTime = EffectiveMinTimeFrame(offender switch
		{
			null => TimeFrame.Zero,
			{ Offense: CoordinatorStabilitySafety } => new TimeFrame(offender.StartedTime, configuration.MinTimeInPrison + TimeSpan.FromHours(new Random().Next(0, 4))),
			{ Offense: FailedToVerify } => new TimeFrame(offender.StartedTime, configuration.MinTimeForFailedToVerify),
			{ Offense: Cheating } => new TimeFrame(offender.StartedTime, configuration.MinTimeForCheating),
			{ Offense: RoundDisruption offense } => new TimeFrame(offender.StartedTime, CalculatePunishment(offender, offense)),
			{ Offense: Inherited { Ancestors: { } ancestors } } => CalculatePunishmentInheritance(ancestors),
			_ => throw new NotSupportedException("Unknown offense type.")
		});

		lock (_lock)
		{
			_banningTimeCache[outpoint] = banningTime;
		}
		return banningTime;
	}

	private void Punish(Offender offender)
	{
		lock (_lock)
		{
			if (_offendersByTxId.TryGetValue(offender.OutPoint.Hash, out var offenders))
			{
				offenders.Add(offender);
			}
			else
			{
				_offendersByTxId.Add(offender.OutPoint.Hash, new List<Offender> { offender });
			}

			_banningTimeCache.Remove(offender.OutPoint);
		}
		if (!_notificationChannelWriter.TryWrite(offender))
		{
			Logger.LogWarning($"Failed to persist offender '{offender.OutPoint}'.");
		}
	}
}
