Well, everyone already knows what it is. No need for explanation :)

NOTE #1: if you want to inject a dll to the same process twice you need to call `FreeLibraryAndExitThread`(https://msdn.microsoft.com/en-us/library/windows/desktop/ms683153(v=vs.85).aspx) in the dll to unload itself. Otherwise the same dll is not gonna load if it is already loaded.
