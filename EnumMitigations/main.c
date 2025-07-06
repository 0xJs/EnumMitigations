#include "common.h"

int main() {
	
	SystemSecuritySettings settings;

	// Initialize struct to zero
	ZeroMemory(&settings, sizeof(SystemSecuritySettings));

	// Collect system security status
	GatherSecuritySettings(&settings);

	// Report results
	ReportSecurityMitigations(&settings);

	return EXIT_SUCCESS;
}