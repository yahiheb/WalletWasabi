using System.Reactive;
using System.Reactive.Concurrency;
using System.Reactive.Linq;
using System.Threading.Tasks;
using System.Windows.Input;
using ReactiveUI;
using WalletWasabi.Fluent.Helpers;
using WalletWasabi.Fluent.Infrastructure;
using WalletWasabi.Fluent.Models.UI;
using WalletWasabi.Fluent.ViewModels.Dialogs.Base;
using WalletWasabi.Fluent.ViewModels.SearchBar.Settings;

namespace WalletWasabi.Fluent.ViewModels.Settings;

[AppLifetime]
[NavigationMetaData(
	Title = "Settings",
	Caption = "Manage appearance, privacy and other settings",
	Order = 1,
	Category = "General",
	Keywords = new[] { "Settings", "General", "User", "Interface", "Advanced" },
	IconName = "nav_settings_24_regular",
	IconNameFocused = "nav_settings_24_filled",
	Searchable = false,
	NavBarPosition = NavBarPosition.Bottom,
	NavigationTarget = NavigationTarget.DialogScreen,
	NavBarSelectionMode = NavBarSelectionMode.Button)]
public partial class SettingsPageViewModel : DialogViewModelBase<Unit>
{
	[AutoNotify] private bool _isModified;
	[AutoNotify] private int _selectedTab;

	public SettingsPageViewModel(UiContext uiContext)
	{
		UiContext = uiContext;
		_selectedTab = 0;

		SetupCancel(enableCancel: true, enableCancelOnEscape: true, enableCancelOnPressed: true);

		CancelCommand = ReactiveCommand.Create(() =>
		{
			UiContext.ApplicationSettings.ResetToDefault();
			return Task.CompletedTask;
		});

		GeneralSettingsTab = new GeneralSettingsTabViewModel(UiContext.ApplicationSettings);
		BitcoinTabSettings = new BitcoinTabSettingsViewModel(UiContext.ApplicationSettings);
		CoordinatorTabSettings = new CoordinatorTabSettingsViewModel(UiContext.ApplicationSettings);
		ConnectionsSettingsTab = new ConnectionsSettingsTabViewModel(UiContext.ApplicationSettings);

		RestartCommand = ReactiveCommand.Create(() => AppLifetimeHelper.Shutdown(withShutdownPrevention: true, restart: true));
		NextCommand = ReactiveCommand.Create(() => Close());

		this.WhenAnyValue(x => x.UiContext.ApplicationSettings.DarkModeEnabled)
			.Skip(1)
			.Subscribe(ChangeTheme);

		// Show restart message when needed
		UiContext.ApplicationSettings.IsRestartNeeded
									 .BindTo(this, x => x.IsModified);

		// Show restart notification when needed only if this page is not active.
		UiContext.ApplicationSettings.IsRestartNeeded
				 .Where(x => x && !IsActive)
				 .Do(_ => NotificationHelpers.Show(new RestartViewModel("To apply the new setting, Wasabi Wallet needs to be restarted")))
				 .Subscribe();
	}

	public bool IsReadOnly => UiContext.ApplicationSettings.IsOverridden;

	public ICommand RestartCommand { get; }

	public GeneralSettingsTabViewModel GeneralSettingsTab { get; }
	public BitcoinTabSettingsViewModel BitcoinTabSettings { get; }
	public CoordinatorTabSettingsViewModel CoordinatorTabSettings { get; }
	public ConnectionsSettingsTabViewModel ConnectionsSettingsTab { get; }

	public async Task Activate()
	{
		await NavigateDialogAsync(this);
	}

	public async Task ActivateCoordinatorTab()
	{
		SelectedTab = 2;
		await NavigateDialogAsync(this);
	}

	private void ChangeTheme(bool isDark)
	{
		RxApp.MainThreadScheduler.Schedule(() => ThemeHelper.ApplyTheme(isDark ? Theme.Dark : Theme.Light));
	}
}
