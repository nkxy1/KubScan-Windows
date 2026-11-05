namespace KubScan.WinUI;

internal static partial class Program
{
    static partial void InitializeGuiRuntime()
    {
#if MICROSOFT_WINDOWSAPPSDK_AUTOINITIALIZE_BOOTSTRAP
        Microsoft.Windows.ApplicationModel.DynamicDependency.BootstrapCS.AutoInitialize.AccessWindowsAppSDK();
#endif
#if MICROSOFT_WINDOWSAPPSDK_AUTOINITIALIZE_DEPLOYMENTMANAGER
        Microsoft.Windows.ApplicationModel.WindowsAppRuntime.DeploymentManagerCS.AutoInitialize.AccessWindowsAppSDK();
#endif
#if MICROSOFT_WINDOWSAPPSDK_AUTOINITIALIZE_UNDOCKEDREGFREEWINRT
        Microsoft.Windows.Foundation.UndockedRegFreeWinRTCS.AutoInitialize.AccessWindowsAppSDK();
#endif
#if MICROSOFT_WINDOWSAPPSDK_AUTOINITIALIZE_COMPATIBILITY
        Microsoft.Windows.ApplicationModel.WindowsAppRuntime.Compatibility.AutoInitialize.ConfigureRuntimeCompatibility();
#endif
    }
}
