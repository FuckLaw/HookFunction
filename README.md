# HookFunction

void UnHookFunction(void* original, BYTE* bytes_originals, int size)
{
	DWORD protect;
	VirtualProtect(original, size, PAGE_EXECUTE_READWRITE, &protect);
	memcpy(original, bytes_originals, size);
	VirtualProtect(original, size, protect, &protect);
}


void HookFunction(void* original, void* hook, int size, BYTE* bytes_saved)
{
	DWORD protect;
	VirtualProtect(original, size, PAGE_EXECUTE_READWRITE, &protect);
	memcpy(bytes_saved, original, size);
	DWORD Difference = (reinterpret_cast<uintptr_t>(hook) - reinterpret_cast<uintptr_t>(original)) - size;
	memset(original, 0x90, size);
	*reinterpret_cast<byte*>(original) = 0xE9;
	*reinterpret_cast<uintptr_t*>(reinterpret_cast<uintptr_t>(original)+1) = Difference;
	VirtualProtect(original, size, protect, &protect);
}
