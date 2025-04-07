#include "common.h"
#include "stdio.h"

/*

	This file is used to store helper functions used within the program, such as print functions

	Use the following section dividers:

	// ***** SECTION ***** //

*/

// ***** HELPER FUNCTIONS FOR PRINTING ***** //

// Function for printing error messages WIN32 API's
int errorWin32(IN const char* msg) {
	error("%s (errorcode: %u)", msg, GetLastError());
}

// Function for printing error messages NT API's
int errorNT(IN const char* msg, NTSTATUS ntstatus) {
	error("%s (NT errorcode: 0x%0.8X)", msg, ntstatus);
}