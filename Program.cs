using System;
using System.Windows.Forms;
using System.Diagnostics;
using System.ComponentModel;
using System.Security.Principal;

namespace NetworkSniffer
{
    static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            WindowsPrincipal pricipal = new WindowsPrincipal(WindowsIdentity.GetCurrent());
            bool hasAdministrativeRight = pricipal.IsInRole(WindowsBuiltInRole.Administrator);

            if (!hasAdministrativeRight)
                RunElevated(Application.ExecutablePath);
            else
            {

                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                Application.Run(new SnifferForm());
            }
        }

        private static void RunElevated(string fileName)
        {
            ProcessStartInfo processInfo = new ProcessStartInfo();
            processInfo.Verb = "runas";
            processInfo.FileName = fileName;
            try
            {
                Process.Start(processInfo);
            }
            catch (Win32Exception)
            {
                //Do nothing. Probably the user canceled the UAC window.
            }
        }
    }
}