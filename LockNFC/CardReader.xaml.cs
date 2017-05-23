using Pcsc;
using Windows.ApplicationModel.Background;
using System;
using static LockNFC.NfcUtils;
using Windows.Devices.SmartCards;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Navigation;
using System.Threading.Tasks;
using Pcsc.Common;
using Windows.UI.Core;
using Windows.Storage.Streams;
using Windows.Security.Cryptography;
using Windows.Security.Authentication.Identity.Provider;
using Windows.UI.Popups;
using System.Collections.Generic;
using System.Linq;
using Windows.ApplicationModel.Core;

// La plantilla de elemento Página en blanco está documentada en https://go.microsoft.com/fwlink/?LinkId=234238

namespace LockNFC
{
    /// <summary>
    /// Una página vacía que se puede usar de forma independiente o a la que se puede navegar dentro de un objeto Frame.
    /// </summary>
    public sealed partial class CardReader : Page
    {
        bool taskRegistered = false;
        static string myBGTaskName = "BgTaskLockNfc";
        static string myBGTaskEntryPoint = "Tasks.BgTaskLockNfc";
        SmartCardReader m_cardReader;

        public CardReader()
        {
            this.InitializeComponent();
            SystemNavigationManager.GetForCurrentView().AppViewBackButtonVisibility = AppViewBackButtonVisibility.Visible;

            UnregisterDevices();
            UnregisterTasks();
        }

        private void UnregisterTasks()
        {
            var tasks = BackgroundTaskRegistration.AllTasks;
            foreach (var task in tasks)
            {
                // You can check here for the name
                string name = task.Value.Name;

                System.Diagnostics.Debug.WriteLine(name);
                task.Value.Unregister(true);
            }
        }


        private async void UnregisterDevices()
        {
            IReadOnlyList<SecondaryAuthenticationFactorInfo> deviceList = await SecondaryAuthenticationFactorRegistration.FindAllRegisteredDeviceInfoAsync(SecondaryAuthenticationFactorDeviceFindScope.AllUsers);

            //DeviceListBox.Items.Clear();

            for (int index = 0; index < deviceList.Count; ++index)
            {
                SecondaryAuthenticationFactorInfo deviceInfo = deviceList.ElementAt(index);
                System.Diagnostics.Debug.WriteLine(deviceInfo.DeviceFriendlyName);
                //DeviceListBox.Items.Add(deviceInfo.DeviceId);

                await SecondaryAuthenticationFactorRegistration.UnregisterDeviceAsync(deviceInfo.DeviceId);
            }

            for (int index = 0; index < deviceList.Count; ++index)
            {
                SecondaryAuthenticationFactorInfo deviceInfo = deviceList.ElementAt(index);
                System.Diagnostics.Debug.WriteLine(deviceInfo.DeviceFriendlyName);
                //DeviceListBox.Items.Add(deviceInfo.DeviceId);

                //await SecondaryAuthenticationFactorRegistration.UnregisterDeviceAsync(deviceInfo.DeviceId);
            }

            //RefreshDeviceList(deviceList);
        }

        protected async override void OnNavigatedTo(NavigationEventArgs e)
        {
            // Clear the messages
            //MainPage.Current.NotifyUser(String.Empty, NotifyType.StatusMessage, true);


            // First try to find a reader that advertises as being NFC
            var deviceInfo = await SmartCardReaderUtils.GetFirstSmartCardReaderInfo(SmartCardReaderKind.Generic);

            if (deviceInfo == null)
            {
                // If we didn't find an NFC reader, let's see if there's a "generic" reader meaning we're not sure what type it is
                deviceInfo = await SmartCardReaderUtils.GetFirstSmartCardReaderInfo(SmartCardReaderKind.Any);
            }

            if (deviceInfo == null)
            {
                LogMessage("NFC card reader mode not supported on this device", NotifyType.ErrorMessage);
                return;
            }

            if (!deviceInfo.IsEnabled)
            {
                var msgbox = new Windows.UI.Popups.MessageDialog("Your NFC proximity setting is turned off, you will be taken to the NFC proximity control panel to turn it on");
                msgbox.Commands.Add(new Windows.UI.Popups.UICommand("OK"));
                await msgbox.ShowAsync();

                // This URI will navigate the user to the NFC proximity control panel
                NfcUtils.LaunchNfcProximitySettingsPage();
                return;
            }

            if (m_cardReader == null)
            {
                m_cardReader = await SmartCardReader.FromIdAsync(deviceInfo.Id);
                m_cardReader.CardAdded += cardReader_CardAdded;
                m_cardReader.CardRemoved += cardReader_CardRemoved;
            }
            //RegisterDevice("test");
        }

        protected override void OnNavigatingFrom(NavigatingCancelEventArgs e)
        {
            // Clean up
            if (m_cardReader != null)
            {
                m_cardReader.CardAdded -= cardReader_CardAdded;
                m_cardReader.CardRemoved -= cardReader_CardRemoved;
                m_cardReader = null;
            }

            base.OnNavigatingFrom(e);
        }

        private void cardReader_CardRemoved(SmartCardReader sender, CardRemovedEventArgs args)
        {
            LogMessage("Card removed");
        }

        private async void cardReader_CardAdded(SmartCardReader sender, CardAddedEventArgs args)
        {
            await HandleCard(args.SmartCard);
        }


        /// <summary>
        /// Sample code to hande a couple of different cards based on the identification process
        /// </summary>
        /// <returns>None</returns>
        private async Task HandleCard(SmartCard card)
        {
            try
            {
                // Clear the messages
                //MainPage.Current.NotifyUser(String.Empty, NotifyType.StatusMessage, true);

                // Connect to the card
                using (SmartCardConnection connection = await card.ConnectAsync())
                {
                    // Try to identify what type of card it was
                    IccDetection cardIdentification = new IccDetection(card, connection);
                    await cardIdentification.DetectCardTypeAync();
                    LogMessage("Connected to card\r\nPC/SC device class: " + cardIdentification.PcscDeviceClass.ToString());
                    LogMessage("Card name: " + cardIdentification.PcscCardName.ToString());
                    LogMessage("ATR: " + BitConverter.ToString(cardIdentification.Atr));

                    if ((cardIdentification.PcscDeviceClass == Pcsc.Common.DeviceClass.StorageClass) &&
                        (cardIdentification.PcscCardName == Pcsc.CardName.MifareUltralightC
                        || cardIdentification.PcscCardName == Pcsc.CardName.MifareUltralight
                        || cardIdentification.PcscCardName == Pcsc.CardName.MifareUltralightEV1))
                    {
                        // Handle MIFARE Ultralight
                        MifareUltralight.AccessHandler mifareULAccess = new MifareUltralight.AccessHandler(connection);

                        // Each read should get us 16 bytes/4 blocks, so doing
                        // 4 reads will get us all 64 bytes/16 blocks on the card
                        for (byte i = 0; i < 4; i++)
                        {
                            byte[] response = await mifareULAccess.ReadAsync((byte)(4 * i));
                            LogMessage("Block " + (4 * i).ToString() + " to Block " + (4 * i + 3).ToString() + " " + BitConverter.ToString(response));
                        }

                        byte[] responseUid = await mifareULAccess.GetUidAsync();
                        LogMessage("UID:  " + BitConverter.ToString(responseUid));
                    }
                    else if (cardIdentification.PcscDeviceClass == Pcsc.Common.DeviceClass.MifareDesfire)
                    {
                        // Handle MIFARE DESfire
                        Desfire.AccessHandler desfireAccess = new Desfire.AccessHandler(connection);
                        Desfire.CardDetails desfire = await desfireAccess.ReadCardDetailsAsync();

                        var UID = BitConverter.ToString(desfire.UID);
                        LogMessage(UID, NotifyType.StatusMessage);

                        LogMessage("DesFire Card Details:  " + Environment.NewLine + desfire.ToString());
                        //Guid g = new Guid(desfire.UID);
                        
                        RegisterDevice(UID);
                    }
                    else if (cardIdentification.PcscDeviceClass == Pcsc.Common.DeviceClass.StorageClass
                        && cardIdentification.PcscCardName == Pcsc.CardName.FeliCa)
                    {
                        // Handle Felica
                        LogMessage("Felica card detected");
                        var felicaAccess = new Felica.AccessHandler(connection);
                        var uid = await felicaAccess.GetUidAsync();
                        LogMessage("UID:  " + BitConverter.ToString(uid));
                    }
                    else if (cardIdentification.PcscDeviceClass == Pcsc.Common.DeviceClass.StorageClass
                        && (cardIdentification.PcscCardName == Pcsc.CardName.MifareStandard1K || cardIdentification.PcscCardName == Pcsc.CardName.MifareStandard4K))
                    {
                        // Handle MIFARE Standard/Classic
                        LogMessage("MIFARE Standard/Classic card detected");
                        var mfStdAccess = new MifareStandard.AccessHandler(connection);
                        var uid = await mfStdAccess.GetUidAsync();
                        LogMessage("UID:  " + BitConverter.ToString(uid));

                        ushort maxAddress = 0;
                        switch (cardIdentification.PcscCardName)
                        {
                            case Pcsc.CardName.MifareStandard1K:
                                maxAddress = 0x3f;
                                RegisterDevice(BitConverter.ToString(uid));
                                break;
                            case Pcsc.CardName.MifareStandard4K:
                                maxAddress = 0xff;
                                break;
                        }
                        await mfStdAccess.LoadKeyAsync(MifareStandard.DefaultKeys.FactoryDefault);

                        for (ushort address = 0; address <= maxAddress; address++)
                        {
                            var response = await mfStdAccess.ReadAsync(address, Pcsc.GeneralAuthenticate.GeneralAuthenticateKeyType.MifareKeyA);
                            LogMessage("Block " + address.ToString() + " " + BitConverter.ToString(response));
                        }
                    }
                    else if (cardIdentification.PcscDeviceClass == Pcsc.Common.DeviceClass.StorageClass
                        && (cardIdentification.PcscCardName == Pcsc.CardName.ICODE1 ||
                            cardIdentification.PcscCardName == Pcsc.CardName.ICODESLI ||
                            cardIdentification.PcscCardName == Pcsc.CardName.iCodeSL2))
                    {
                        // Handle ISO15693
                        LogMessage("ISO15693 card detected");
                        var iso15693Access = new Iso15693.AccessHandler(connection);
                        var uid = await iso15693Access.GetUidAsync();
                        LogMessage("UID:  " + BitConverter.ToString(uid));
                    }
                    else
                    {
                        // Unknown card type
                        // Note that when using the XDE emulator the card's ATR and type is not passed through, so we'll
                        // end up here even for known card types if using the XDE emulator

                        // Some cards might still let us query their UID with the PC/SC command, so let's try:
                        var apduRes = await connection.TransceiveAsync(new Pcsc.GetUid());
                        if (!apduRes.Succeeded)
                        {
                            LogMessage("Failure getting UID of card, " + apduRes.ToString());
                        }
                        else
                        {
                            LogMessage("UID:  " + BitConverter.ToString(apduRes.ResponseData));
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                LogMessage("Exception handling card: " + ex.ToString(), NotifyType.ErrorMessage);
            }
        }

        private async void RegisterDevice(string uid)
        {
            String deviceId = System.Guid.NewGuid().ToString();
            //String deviceId = uid;

            // WARNING: Test code
            // These keys should be generated on the companion device
            // Create device key and authentication key
            IBuffer deviceKey = CryptographicBuffer.GenerateRandom(32);
            IBuffer authKey = CryptographicBuffer.GenerateRandom(32);

            //
            // WARNING: Test code
            // The keys SHOULD NOT be saved into device config data
            //
            byte[] deviceKeyArray = { 0 };
            CryptographicBuffer.CopyToByteArray(deviceKey, out deviceKeyArray);

            byte[] authKeyArray = { 0 };
            CryptographicBuffer.CopyToByteArray(authKey, out authKeyArray);

            //Generate combinedDataArray
            int combinedDataArraySize = deviceKeyArray.Length + authKeyArray.Length;
            byte[] combinedDataArray = new byte[combinedDataArraySize];
            for (int index = 0; index < deviceKeyArray.Length; index++)
            {
                combinedDataArray[index] = deviceKeyArray[index];
            }
            for (int index = 0; index < authKeyArray.Length; index++)
            {
                combinedDataArray[deviceKeyArray.Length + index] = authKeyArray[index];
            }

            // Get a Ibuffer from combinedDataArray
            IBuffer deviceConfigData = CryptographicBuffer.CreateFromByteArray(combinedDataArray);

            //
            // WARNING: Test code
            // The friendly name and device model number SHOULD come from device
            //
            String deviceFriendlyName = "Test Simulator";
            String deviceModelNumber = "Sample A1";

            SecondaryAuthenticationFactorDeviceCapabilities capabilities = SecondaryAuthenticationFactorDeviceCapabilities.SecureStorage;

            SecondaryAuthenticationFactorRegistrationResult registrationResult = await SecondaryAuthenticationFactorRegistration.RequestStartRegisteringDeviceAsync(deviceId,
                    capabilities,
                    deviceFriendlyName,
                    deviceModelNumber,
                    deviceKey,
                    authKey);

            if (registrationResult.Status != SecondaryAuthenticationFactorRegistrationStatus.Started)
            {
                MessageDialog myDlg = null;

                if (registrationResult.Status == SecondaryAuthenticationFactorRegistrationStatus.DisabledByPolicy)
                {
                    //For DisaledByPolicy Exception:Ensure secondary auth is enabled.
                    //Use GPEdit.msc to update group policy to allow secondary auth
                    //Local Computer Policy\Computer Configuration\Administrative Templates\Windows Components\Microsoft Secondary Authentication Factor\Allow Companion device for secondary authentication
                    myDlg = new MessageDialog("Disabled by Policy.  Please update the policy and try again.");
                }

                if (registrationResult.Status == SecondaryAuthenticationFactorRegistrationStatus.PinSetupRequired)
                {
                    //For PinSetupRequired Exception:Ensure PIN is setup on the device
                    //Either use gpedit.msc or set reg key
                    //This setting can be enabled by creating the AllowDomainPINLogon REG_DWORD value under the HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System Registry key and setting it to 1.
                    myDlg = new MessageDialog("Please setup PIN for your device and try again.");
                }

                if (myDlg != null)
                {
                    await myDlg.ShowAsync();
                    return;
                }
            }

            System.Diagnostics.Debug.WriteLine("Device Registration Started!");
            await registrationResult.Registration.FinishRegisteringDeviceAsync(deviceConfigData);

            //DeviceListBox.Items.Add(deviceId);
            System.Diagnostics.Debug.WriteLine("Device Registration is Complete!");

            IReadOnlyList<SecondaryAuthenticationFactorInfo> deviceList = await SecondaryAuthenticationFactorRegistration.FindAllRegisteredDeviceInfoAsync(
                SecondaryAuthenticationFactorDeviceFindScope.User);

            //RefreshDeviceList(deviceList);
            var localSettings = Windows.Storage.ApplicationData.Current.LocalSettings;
            for (int index = 0; index < deviceList.Count; ++index)
            {
                SecondaryAuthenticationFactorInfo deviceInfo = deviceList.ElementAt(index);
                //Store the selected device in settings to be used in the BG task
                localSettings.Values["SelectedDevice"] = uid;
            }
            DisplayTaskCreatedDialog("Device registration is complete!.");
            RegisterTask();
        }



        private async void OnBgTaskProgress(BackgroundTaskRegistration sender, BackgroundTaskProgressEventArgs args)
        {
            // WARNING: Test code
            // Handle background task progress.
            if (args.Progress == 1)
            {
                await CoreApplication.MainView.CoreWindow.Dispatcher.RunAsync(CoreDispatcherPriority.Normal, () =>
                {
                    System.Diagnostics.Debug.WriteLine("Background task is started.");
                    //DisplayTaskCreatedDialog("Background task is started.");
                });
            }
        }

        async void RegisterTask()
        {
            System.Diagnostics.Debug.WriteLine("Register the background task.");
            //
            // Check for existing registrations of this background task.
            //
            
            BackgroundExecutionManager.RemoveAccess();
            var access = await BackgroundExecutionManager.RequestAccessAsync();

            foreach (var task in BackgroundTaskRegistration.AllTasks)
            {
                if (task.Value.Name == myBGTaskName)
                {
                    System.Diagnostics.Debug.WriteLine("Task already registered");
                    taskRegistered = true;
                    break;
                }
            }

            if (!taskRegistered)
            {
                System.Diagnostics.Debug.WriteLine("Registering  Task");

                if (access == BackgroundAccessStatus.AllowedSubjectToSystemPolicy)
                {
                    BackgroundTaskBuilder taskBuilder = new BackgroundTaskBuilder()
                    {
                        Name = myBGTaskName
                    };
                    // Create the trigger.
                    SecondaryAuthenticationFactorAuthenticationTrigger myTrigger = new SecondaryAuthenticationFactorAuthenticationTrigger();

                    taskBuilder.TaskEntryPoint = myBGTaskEntryPoint;
                    taskBuilder.SetTrigger(myTrigger);
                    BackgroundTaskRegistration taskReg = taskBuilder.Register();

                    String taskRegName = taskReg.Name;
                    taskReg.Progress += OnBgTaskProgress;
                    System.Diagnostics.Debug.WriteLine("Background task registration is completed.");
                    taskRegistered = true;
                }
            }

        }

        private async void DisplayTaskCreatedDialog(string message)
        {
            /*ContentDialog noWifiDialog = new ContentDialog
            {
                Title = "Algo ocurrió",
                Content = message,
                CloseButtonText = "OK"
            };

            ContentDialogResult result = await noWifiDialog.ShowAsync();*/

            System.Diagnostics.Debug.WriteLine(message);
        }

        private void Button_Click(object sender, Windows.UI.Xaml.RoutedEventArgs e)
        {
            RegisterTask();
        }
    }
}
