using System;
using System.Runtime.Intrinsics;

namespace Blake2b.NetCore
{
    internal static class Blake2bRuntimeFeatures
    {
        private const string DisableSimdSwitchName = "Blake2b.NetCore.DisableSimd";

        internal static bool UseSimd
        {
            get
            {
                AppContext.TryGetSwitch(DisableSimdSwitchName, out var disableSimd);
                return Vector128.IsHardwareAccelerated && BitConverter.IsLittleEndian && !disableSimd;
            }
        }
    }
}
