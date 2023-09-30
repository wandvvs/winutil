#include "winutil.h"

int main() {
	try {
		WinUtil::convertFromBinary("C:\\to.txt", "C:\\from.txt");
	}
	catch (WinException ex) {
		std::cout << ex.what() << std::endl;
	}
}