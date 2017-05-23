using Pcsc;
using Pcsc.Common;
using System;
using System.Diagnostics;
using System.Threading.Tasks;
using Windows.ApplicationModel.Background;
using Windows.ApplicationModel.Core;
using Windows.Devices.SmartCards;
using Windows.UI.Core;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Navigation;
using static LockNFC.NfcUtils;
using static Tasks.BgTaskLockNfc;

// La plantilla de elemento Página en blanco está documentada en https://go.microsoft.com/fwlink/?LinkId=402352&clcid=0xc0a

namespace LockNFC
{
    /// <summary>
    /// Página vacía que se puede usar de forma independiente o a la que se puede navegar dentro de un objeto Frame.
    /// </summary>
    public sealed partial class MainPage : Page
    {

        bool taskRegistered = false;
        static string myBGTaskName = "BgTaskLockNfc";
        static string myBGTaskEntryPoint = "Tasks.BgTaskLockNfc";

        public MainPage()
        {
            this.InitializeComponent();
            String deviceId = System.Guid.NewGuid().ToString();
            System.Diagnostics.Debug.WriteLine(deviceId);
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

        private void Button_Click(object sender, Windows.UI.Xaml.RoutedEventArgs e)
        {
            // Navigate to MyNewPage.xaml  
            this.Frame.Navigate(typeof(CardReader));
        }

        private void Button_Click_1(object sender, Windows.UI.Xaml.RoutedEventArgs e)
        {
            //UnregisterTasks();
            RegisterTask();
        }

        private async void OnBgTaskProgress(BackgroundTaskRegistration sender, BackgroundTaskProgressEventArgs args)
        {
            // WARNING: Test code
            // Handle background task progress.
            System.Diagnostics.Debug.WriteLine(args);
            if (args.Progress == 1)
            {
                await Dispatcher.RunAsync(CoreDispatcherPriority.Normal, () =>
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
                    taskRegistered = true;
                    break;
                }
            }

            if (!taskRegistered)
            {

                if (access == BackgroundAccessStatus.AllowedSubjectToSystemPolicy)
                {
                    BackgroundTaskBuilder taskBuilder = new BackgroundTaskBuilder();
                    taskBuilder.Name = myBGTaskName;
                    // Create the trigger.
                    SecondaryAuthenticationFactorAuthenticationTrigger myTrigger = new SecondaryAuthenticationFactorAuthenticationTrigger();

                    taskBuilder.TaskEntryPoint = myBGTaskEntryPoint;
                    taskBuilder.SetTrigger(myTrigger);
                    BackgroundTaskRegistration taskReg = taskBuilder.Register();

                    String taskRegName = taskReg.Name;
                    //taskReg.Progress += OnBgTaskProgress;
                    System.Diagnostics.Debug.WriteLine("Background task registration is completed.");
                    taskRegistered = true;
                }
            }

        }
    }
}
