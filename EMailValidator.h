#pragma once

namespace EmailValidation
{
	bool Validate(const wchar_t* pszEmail, const bool bAllowTopLevelDomains = false, const bool bAllowInternational = false);
	bool Validate(const char* pszEmail, const bool bAllowTopLevelDomains = false, const bool bAllowInternational = false);
}

