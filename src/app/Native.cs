// =============================================================================
// Native.cs -- the few Win32 calls WPF doesn't wrap
// =============================================================================

using System;
using System.Runtime.InteropServices;

namespace TriageToolkit
{
    static class Native
    {
        // ----- dark title bar (Windows 10 2004+ / 11) ---------------------------
        [DllImport("dwmapi.dll")]
        static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);

        const int DWMWA_USE_IMMERSIVE_DARK_MODE_OLD = 19;
        const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;
        const int DWMWA_CAPTION_COLOR = 35;
        const int DWMWA_TEXT_COLOR = 36;

        public static void UseDarkTitleBar(IntPtr hwnd, byte r, byte g, byte b)
        {
            try
            {
                int on = 1;
                if (DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, ref on, 4) != 0)
                    DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE_OLD, ref on, 4);
                int caption = r | (g << 8) | (b << 16);          // COLORREF is 0x00BBGGRR
                DwmSetWindowAttribute(hwnd, DWMWA_CAPTION_COLOR, ref caption, 4);   // Windows 11 only; ignored elsewhere
                int text = 0xF2 | (0xEA << 8) | (0xE6 << 16);
                DwmSetWindowAttribute(hwnd, DWMWA_TEXT_COLOR, ref text, 4);
            }
            catch { /* cosmetic */ }
        }

        // ----- taskbar flash when a scan finishes in the background ------------
        [StructLayout(LayoutKind.Sequential)]
        struct FLASHWINFO
        {
            public uint cbSize;
            public IntPtr hwnd;
            public uint dwFlags;
            public uint uCount;
            public uint dwTimeout;
        }

        [DllImport("user32.dll")]
        static extern bool FlashWindowEx(ref FLASHWINFO pwfi);

        public static void FlashUntilFocused(IntPtr hwnd)
        {
            try
            {
                var fi = new FLASHWINFO
                {
                    cbSize = (uint)Marshal.SizeOf(typeof(FLASHWINFO)),
                    hwnd = hwnd,
                    dwFlags = 3 | 12,   // FLASHW_ALL | FLASHW_TIMERNOFG
                };
                FlashWindowEx(ref fi);
            }
            catch { }
        }

        // ----- console for --headless -------------------------------------------
        [DllImport("kernel32.dll")]
        public static extern bool AttachConsole(int pid);

        [DllImport("kernel32.dll")]
        public static extern bool AllocConsole();

        // ----- modern folder picker (IFileOpenDialog + FOS_PICKFOLDERS) ---------
        // System.Windows.Forms.FolderBrowserDialog on .NET Framework is the old
        // tree view; this is the same dialog Explorer uses.
        public static string PickFolder(IntPtr owner, string title, string initial)
        {
            IFileOpenDialog dlg = null;
            try
            {
                dlg = (IFileOpenDialog)new FileOpenDialogRCW();
                uint opts;
                dlg.GetOptions(out opts);
                dlg.SetOptions(opts | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST);
                if (!string.IsNullOrEmpty(title)) dlg.SetTitle(title);
                if (!string.IsNullOrEmpty(initial) && System.IO.Directory.Exists(initial))
                {
                    IShellItem folder;
                    Guid iid = typeof(IShellItem).GUID;
                    if (SHCreateItemFromParsingName(initial, IntPtr.Zero, ref iid, out folder) == 0)
                        dlg.SetFolder(folder);
                }
                if (dlg.Show(owner) != 0) return null;   // cancelled
                IShellItem item;
                dlg.GetResult(out item);
                string path;
                item.GetDisplayName(SIGDN_FILESYSPATH, out path);
                return path;
            }
            catch { return null; }
            finally { if (dlg != null) Marshal.ReleaseComObject(dlg); }
        }

        const uint FOS_PICKFOLDERS = 0x20, FOS_FORCEFILESYSTEM = 0x40, FOS_PATHMUSTEXIST = 0x800;
        const uint SIGDN_FILESYSPATH = 0x80058000;

        [DllImport("shell32.dll", CharSet = CharSet.Unicode, PreserveSig = true)]
        static extern int SHCreateItemFromParsingName(string path, IntPtr pbc, ref Guid riid, out IShellItem item);

        [ComImport, Guid("DC1C5A9C-E88A-4dde-A5A1-60F82A20AEF7")]
        class FileOpenDialogRCW { }

        [ComImport, Guid("d57c7288-d4ad-4768-be02-9d969532d960"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        interface IFileOpenDialog
        {
            [PreserveSig] int Show(IntPtr parent);
            void SetFileTypes();
            void SetFileTypeIndex();
            void GetFileTypeIndex();
            void Advise();
            void Unadvise();
            void SetOptions(uint fos);
            void GetOptions(out uint fos);
            void SetDefaultFolder(IShellItem psi);
            void SetFolder(IShellItem psi);
            void GetFolder();
            void GetCurrentSelection();
            void SetFileName([MarshalAs(UnmanagedType.LPWStr)] string name);
            void GetFileName();
            void SetTitle([MarshalAs(UnmanagedType.LPWStr)] string title);
            void SetOkButtonLabel();
            void SetFileNameLabel();
            void GetResult(out IShellItem psi);
            // remaining members unused
        }

        [ComImport, Guid("43826D1E-E718-42EE-BC55-A1E261C37BFE"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        interface IShellItem
        {
            void BindToHandler();
            void GetParent();
            void GetDisplayName(uint sigdn, [MarshalAs(UnmanagedType.LPWStr)] out string name);
            void GetAttributes();
            void Compare();
        }
    }
}
