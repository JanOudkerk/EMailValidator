#include "stdafx.h"
#include <string>
#include <stdexcept>
#include "EMailValidator.h"


//
// EmailValidator.cs
//
// Author: Jeffrey Stedfast <jestedfa@microsoft.com>
//
// Copyright (c) 2013-2017 Jeffrey Stedfast
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.


// EMailValidator.cpp: translation from C# to C++: Jan Oudkerk <jan.oudkerk@vertimart.nl>, august 2020.

namespace EmailValidation
{
	/// <summary>
	/// An Email validator.
	/// </summary>

	class CEmailValidator
	{
	private:
		enum class SubDomainType {
			None			= 0,
			Alphabetic		= 1,
			Numeric			= 2,
			AlphaNumeric	= 3
		};

		static bool IsDigit(const wchar_t c)
		{
			return (c >= '0' && c <= '9');
		}

		static bool IsLetter(const wchar_t c)
		{
			return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
		}

		static bool IsLetterOrDigit(const wchar_t c)
		{
			return IsLetter(c) || IsDigit(c);
		}

		static bool IsAtom(const wchar_t c, const bool allowInternational)
		{
			static const std::wstring Atomcharacters(L"!#$%&'*+-/=?^_`{|}~");

			return c < 128	? IsLetterOrDigit(c) || Atomcharacters.find(c) != std::string::npos 
							: allowInternational;
		}

		static bool IsDomain(const wchar_t c, const bool allowInternational, SubDomainType *pType)
		{
			if (c < 128) {
				if (IsLetter(c) || c == '-') {
					*pType = XORSubDomainType(*pType, SubDomainType::Alphabetic);
					return true;
				}

				if (IsDigit(c)) {
					*pType = XORSubDomainType(*pType, SubDomainType::Numeric);
					return true;
				}

				return false;
			}

			if (allowInternational) {
				*pType = XORSubDomainType(*pType, SubDomainType::Alphabetic);
				return true;
			}

			return false;
		}

		static bool IsDomainStart(const wchar_t c, const bool allowInternational, SubDomainType *pType)
		{
			if (c < 128) {
				if (IsLetter(c)) {
					*pType = XORSubDomainType(*pType, SubDomainType::Alphabetic);
					return true;
				}

				if (IsDigit(c)) {
					*pType = XORSubDomainType(*pType, SubDomainType::Numeric);
					return true;
				}

				*pType = SubDomainType::None;

				return false;
			}

			if (allowInternational) {
				*pType = XORSubDomainType(*pType, SubDomainType::Alphabetic);
				return true;
			}

			*pType = SubDomainType::None;

			return false;
		}

		static bool SkipAtom(const wchar_t *pszText, int *pIndex, const bool allowInternational)
		{
			const int startIndex = *pIndex;

			const int iLenText = wcslen(pszText);

			while (*pIndex < iLenText && IsAtom(pszText[*pIndex], allowInternational))
				(*pIndex)++;

			return *pIndex > startIndex;
		}

		static bool SkipSubDomain(const wchar_t *pszText, int *pIndex, const bool allowInternational, SubDomainType *pType)
		{
			const int startIndex = *pIndex;

			if (!IsDomainStart(pszText[*pIndex], allowInternational, pType))
				return false;

			(*pIndex)++;

			const int iLenText = wcslen(pszText);
			while (*pIndex < iLenText && IsDomain(pszText[*pIndex], allowInternational, pType))
				(*pIndex)++;

			return (*pIndex - startIndex) < 64 && pszText[*pIndex - 1] != '-';
		}

		static bool SkipDomain(const wchar_t *pszText, int *pIndex, const bool allowTopLevelDomains, const bool allowInternational)
		{
			SubDomainType type = SubDomainType::None;

			if (!SkipSubDomain(pszText, pIndex, allowInternational, &type))
				return false;

			const int iLenText = wcslen(pszText);
			if (*pIndex < iLenText && pszText[*pIndex] == '.') {
				do {
					(*pIndex)++;

					if (*pIndex == iLenText)
						return false;

					if (!SkipSubDomain(pszText, pIndex, allowInternational, &type))
						return false;
				} while (*pIndex < iLenText && pszText[*pIndex] == '.');
			}
			else if (!allowTopLevelDomains) {
				return false;
			}

			// Note: by allowing AlphaNumeric, we get away with not having to support punycode.
			if (type == SubDomainType::Numeric)
				return false;

			return true;
		}

		static bool SkipQuoted(const wchar_t *pszText, int *pIndex, const bool allowInternational)
		{
			bool escaped = false;

			// skip over leading '"'
			(*pIndex)++;

			const int iLenText = wcslen(pszText);
			while (*pIndex < iLenText) {
				if (pszText[*pIndex] >= 128 && !allowInternational)
					return false;

				if (pszText[*pIndex] == '\\') {
					escaped = !escaped;
				}
				else if (!escaped) {
					if (pszText[*pIndex] == '"')
						break;
				}
				else {
					escaped = false;
				}

				(*pIndex)++;
			}

			if (*pIndex >= iLenText || pszText[*pIndex] != '"')
				return false;

			(*pIndex)++;

			return true;
		}

		static bool SkipIPv4Literal(const wchar_t *pszText, int *pIndex)
		{
			int groups = 0;

			const int iLenText = wcslen(pszText);
			while (*pIndex < iLenText && groups < 4) {
				const int startIndex = *pIndex;
				int value = 0;

				while (*pIndex < iLenText && pszText[*pIndex] >= '0' && pszText[*pIndex] <= '9') {
					value = (value * 10) + (pszText[*pIndex] - '0');
					(*pIndex)++;
				}

				if (*pIndex == startIndex || *pIndex - startIndex > 3 || value > 255)
					return false;

				groups++;

				if (groups < 4 && *pIndex < iLenText && pszText[*pIndex] == '.')
					(*pIndex)++;
			}

			return groups == 4;
		}

		static bool IsHexDigit(const wchar_t c)
		{
			return (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f') || (c >= '0' && c <= '9');
		}

		// This needs to handle the following forms:
		//
		// IPv6-addr = IPv6-full / IPv6-comp / IPv6v4-full / IPv6v4-comp
		// IPv6-hex  = 1*4HEXDIG
		// IPv6-full = IPv6-hex 7(":" IPv6-hex)
		// IPv6-comp = [IPv6-hex *5(":" IPv6-hex)] "::" [IPv6-hex *5(":" IPv6-hex)]
		//             ; The "::" represents at least 2 16-bit groups of zeros
		//             ; No more than 6 groups in addition to the "::" may be
		//             ; present
		// IPv6v4-full = IPv6-hex 5(":" IPv6-hex) ":" IPv4-address-literal
		// IPv6v4-comp = [IPv6-hex *3(":" IPv6-hex)] "::"
		//               [IPv6-hex *3(":" IPv6-hex) ":"] IPv4-address-literal
		//             ; The "::" represents at least 2 16-bit groups of zeros
		//             ; No more than 4 groups in addition to the "::" and
		//             ; IPv4-address-literal may be present
		static bool SkipIPv6Literal(const wchar_t *pszText, int *pIndex)
		{
			bool compact = false;
			int colons = 0;

			const int iLenText = wcslen(pszText);
			while (*pIndex < iLenText) {
				int startIndex = *pIndex;

				while (*pIndex < iLenText && IsHexDigit(pszText[*pIndex]))
					(*pIndex)++;

				if (*pIndex >= iLenText)
					break;

				if (*pIndex > startIndex && colons > 2 && pszText[*pIndex] == '.') {
					// IPv6v4
					*pIndex = startIndex;

					if (!SkipIPv4Literal(pszText, pIndex))
						return false;

					return compact ? colons < 6 : colons == 6;
				}

				int count = *pIndex - startIndex;
				if (count > 4)
					return false;

				if (pszText[*pIndex] != ':')
					break;

				startIndex = *pIndex;
				while (*pIndex < iLenText && pszText[*pIndex] == ':')
					(*pIndex)++;

				count = *pIndex - startIndex;
				if (count > 2)
					return false;

				if (count == 2) {
					if (compact)
						return false;

					compact = true;
					colons += 2;
				}
				else {
					colons++;
				}
			}

			if (colons < 2)
				return false;

			return compact ? colons < 7 : colons == 7;
		}

		static SubDomainType XORSubDomainType(const SubDomainType type, const SubDomainType typeToXOR)
		{
			if (SubDomainType::None == type || typeToXOR == type)
			{
				return typeToXOR;
			}
			if (SubDomainType::AlphaNumeric == type)
			{
				return type;
			}
			if (SubDomainType::Alphabetic == type || SubDomainType::Numeric == type)
			{
				return SubDomainType::AlphaNumeric;
			}
			ASSERT(0);
			return SubDomainType::None;
		}

		// JO, aug 2020
		static bool	IsLengthOfTopLevelDomainOK(const wchar_t *pszEMail)
		{
			const wchar_t* pAt = wcsrchr(pszEMail, '@');
			if (pAt)
			{
				const wchar_t* pDot = wcsrchr(pszEMail, '.');
				if (pDot)
				{
					if (pDot > pAt)
					{
						const int iLen = wcslen(pDot) - 1;
						return iLen >= 2;	
					}
				}
			}
			return false;
		}

	public:

		/// <summary>
		/// Validate the specified email address.
		/// </summary>
		/// <remarks>
		/// <para>Validates the syntax of an email address.</para>
		/// <para>If <paramref name="allowTopLevelDomains"/> is <c>true</c>, then the validator will
		/// allow addresses with top-level domains like <c>postmaster@dk</c>.</para>
		/// <para>If <paramref name="allowInternational"/> is <c>true</c>, then the validator
		/// will use the newer International Email standards for validating the email address.</para>
		/// </remarks>
		/// <returns><c>true</c> if the email address is valid; otherwise, <c>false</c>.</returns>
		/// <param name="email">An email address.</param>
		/// <param name="allowTopLevelDomains"><c>true</c> if the validator should allow addresses at top-level domains; otherwise, <c>false</c>.</param>
		/// <param name="allowInternational"><c>true</c> if the validator should allow international wchar_tacters; otherwise, <c>false</c>.</param>
		/// <exception cref="System.ArgumentNullException">
		/// <paramref name="email"/> is <c>null</c>.
		/// </exception>
		static bool Validate(const wchar_t *pszEmail, const bool allowTopLevelDomains = false, const bool allowInternational = false)
		{
			int index = 0;

			if (nullptr == pszEmail)
				throw new std::invalid_argument("e-mail");

			const int iLenText = wcslen(pszEmail);
			if (iLenText == 0 || iLenText >= 255)
				return false;

			if (!IsLengthOfTopLevelDomainOK(pszEmail))
			{
				return false;
			}

			// Local-part = Dot-string / Quoted-string
			//       ; MAY be case-sensitive
			//
			// Dot-string = Atom *("." Atom)
			//
			// Quoted-string = DQUOTE *qcontent DQUOTE
			if (pszEmail[index] == '"') {
				if (!SkipQuoted(pszEmail, &index, allowInternational) || index >= iLenText)
					return false;
			}
			else {
				if (!SkipAtom(pszEmail, &index, allowInternational) || index >= iLenText)
					return false;

				while (pszEmail[index] == '.') {
					index++;

					if (index >= iLenText)
						return false;

					if (!SkipAtom(pszEmail, &index, allowInternational))
						return false;

					if (index >= iLenText)
						return false;
				}
			}

			if (index + 1 >= iLenText || index > 64 || pszEmail[index++] != '@')
				return false;

			if (pszEmail[index] != '[') {
				// domain
				if (!SkipDomain(pszEmail, &index, allowTopLevelDomains, allowInternational))
					return false;

				return index == iLenText;
			}

			// address literal
			index++;

			// we need at least 8 more wchar_tacters
			if (index + 8 >= iLenText)
				return false;

			wchar_t szIPv6[8] = { 0 };
			wcsncpy_s(szIPv6, _countof(szIPv6), &pszEmail[index], 5);
			if ( !_wcsicmp(szIPv6, L"ipv6:"))		{
				index += wcslen(szIPv6);
				if (!SkipIPv6Literal(pszEmail, &index))
					return false;
			}
			else {
				if (!SkipIPv4Literal(pszEmail, &index))
					return false;
			}

			if (index >= iLenText || pszEmail[index++] != ']')
				return false;

			return index == iLenText;
		}

		static bool Validate(const char* pszEmail, const bool allowTopLevelDomains = false, const bool allowInternational = false)
		{
			return Validate(CA2W(pszEmail), allowTopLevelDomains, allowInternational);
		}
	};


	///////////////////////////////////////////////////////////////////////////
	bool Validate(const wchar_t* pszEmail, const bool bAllowTopLevelDomains/*= false*/, const bool bAllowInternational/*= false*/)
	{
		return CEmailValidator::Validate(pszEmail, bAllowTopLevelDomains, bAllowInternational);
	}

	bool Validate(const char* pszEmail, const bool bAllowTopLevelDomains/*= false*/, const bool bAllowInternational/*= false*/)
	{
		return CEmailValidator::Validate(pszEmail, bAllowTopLevelDomains, bAllowInternational);
	}



}

