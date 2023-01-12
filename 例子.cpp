#include "Android-Memory-Debug.hpp"

int main()
{

	MemoryDebug md;
	md.setPackageName("tv.danmaku.bili");



	md.searchMem < int >(2234, DWORD, Mem_Ca);
	md.SearchOffest < int >(2234, 0);
	md.SearchOffest < int >(46, 0x4);
	md.SearchOffest < int >(120, -0x4);
	md.Editoffest < int >(9999, 0x8);

	return 0;
}
