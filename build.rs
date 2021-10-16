fn main() {
    windows::build!(
        Windows::Win32::UI::WindowsAndMessaging::FindWindowA,
        Windows::Win32::Foundation::{HANDLE, CloseHandle, HINSTANCE, PSTR},
        Windows::Win32::System::Threading::{OpenProcess, PROCESS_ACCESS_RIGHTS},
        Windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32},
        Windows::Win32::System::SystemServices::CHAR,
        Windows::Win32::System::Diagnostics::Debug::ReadProcessMemory,
        Windows::Win32::System::Diagnostics::Debug::GetLastError,
        Windows::Win32::System::ProcessStatus::{K32EnumProcessModules, K32GetModuleFileNameExA},
    )
}
