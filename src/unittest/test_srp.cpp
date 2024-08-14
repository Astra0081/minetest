/*
Minetest
Copyright (C) 2024 red-001 <red-001@outlook.ie>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation; either version 2.1 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "test.h"

#include "util/numeric.h"
#include "util/string.h"
#include "util/base64.h"
#include "util/srp.h"
#include "util/auth.h"
#include <my_sha256.h>

static const std::string g_username = "Cthon98";
static const std::string g_password = "hunter2";
static const std::string g_wrong_password = "HorseBattery";
// An SRP DB-formatted verifier+salt for the user "Cthon98" with the password "hunter2"
static const std::string g_cthon98SRPHash = "#1#5RTUx9R8W4EYkHXMkpXfew#WhYGdt62"
"d4sJ8E91PpmTdLKY0h0WvxPG19jBq6inMOcUxARA24JkwmQJBIFNJBz90RbYdlqLwuZ5C3+rGxP7Ng"
"8FkoSweJPu7X3d+NFfmIG1bGH395xSq1C44nMZlMi/5EUeDOJXUX89NXm1G4Xde+IU3PjI9719mOAX"
"N279rraLVvk9t5jJK5N7HX/Oz3rjGZpXmF4+s/x3PRrrzTHpP3muMXC2vwwIiB2Mb7t/r/GE9NlVtW"
"rmLZhiNurNpPTyBF/w7gjTfUVd7XbfAZHm0ixaH3FfgRwr821QL3KH2TxhBvLZu3t4GYeQpQynwPmS"
"sexJ7vqafwtNAak3t+dS5A";

class TestSRP : public TestBase {
public:
	TestSRP() { TestManager::registerTestModule(this); }
	const char* getName() { return "TestSRP"; }

	void runTests(IGameDef* gamedef);

	void testSRPVerifierRoundTripDB();
	void testLoginKnownVerifier();
	void testLoginFullRandomVerifierLegacy();
	void testLoginFullRandomVerifierEncryptedNet();

	void testLoginFullRandomVerifier(u8* extra_state_data, size_t extra_state_len, bool server_should_lie);
	bool testLoginWithPasswordAndVerifier(const std::string& verifier, const std::string& salt, const std::string& password_client, bool server_should_lie, u8 *extra_state_data, size_t extra_state_len);
	bool testLoginWithPassword(const std::string& password, const std::string& password_client, bool server_should_lie, u8* extra_state_data, size_t extra_state_len)
	{
		std::string verifier;
		std::string salt;
		generate_srp_verifier_and_salt(g_username, password, &verifier, &salt);

		return testLoginWithPasswordAndVerifier(verifier, salt, password_client, server_should_lie, extra_state_data, extra_state_len);
	}
	bool testLoginWithPasswordAndDBVerifer(const std::string& enc_verifier, const std::string& password_client, bool server_should_lie, u8* extra_state_data, size_t extra_state_len)
	{
		std::string verifier;
		std::string salt;
		UASSERT(decode_srp_verifier_and_salt(enc_verifier, &verifier, &salt));

		return testLoginWithPasswordAndVerifier(verifier, salt, password_client, server_should_lie, extra_state_data, extra_state_len);
	}
};

static TestSRP g_test_instance;

void TestSRP::runTests(IGameDef* gamedef)
{
	TEST(testSRPVerifierRoundTripDB);
	TEST(testLoginKnownVerifier);
	TEST(testLoginFullRandomVerifierLegacy);
	TEST(testLoginFullRandomVerifierEncryptedNet);
}

void TestSRP::testLoginFullRandomVerifierLegacy()
{
	testLoginFullRandomVerifier(NULL, 0, false);
	testLoginFullRandomVerifier(NULL, 0, true);
}

void TestSRP::testLoginFullRandomVerifierEncryptedNet()
{
	// generate random extra state
	u8 extra_state[32];
	for (u8& s : extra_state)
		s = rand();
	testLoginFullRandomVerifier(extra_state, sizeof(extra_state), false);
	testLoginFullRandomVerifier(extra_state, sizeof(extra_state), true);
}

void TestSRP::testLoginFullRandomVerifier(u8* extra_state_data, size_t extra_state_len, bool server_should_lie)
{
	// test 50 correct and 50 incorrect logins
	// and see that each fails or passes as expected
	for (size_t i = 0; i < 50; i++)
	{
		UASSERTEQ(bool, testLoginWithPassword(g_password, g_password, server_should_lie, extra_state_data, extra_state_len), true);
		UASSERTEQ(bool, testLoginWithPassword(g_password, g_wrong_password, server_should_lie, extra_state_data, extra_state_len), false);
	}
}

void TestSRP::testLoginKnownVerifier()
{
	// test 100 correct and 100 incorrect logins
	// and see that each fails or passes as expected
	for (size_t i = 0; i < 100; i++)
	{
		UASSERTEQ(bool, testLoginWithPasswordAndDBVerifer(g_cthon98SRPHash, g_password, false, nullptr, 0), true);
		UASSERTEQ(bool, testLoginWithPasswordAndDBVerifer(g_cthon98SRPHash, g_wrong_password, false, nullptr, 0), false);
	}
}

void TestSRP::testSRPVerifierRoundTripDB()
{
	std::string verifier;
	std::string salt;
	generate_srp_verifier_and_salt(g_username, g_password, &verifier, &salt);

	const std::string encoded_srp_verifier = encode_srp_verifier(verifier, salt);

	std::string d_verifier;
	std::string d_salt;
	UASSERT(decode_srp_verifier_and_salt(encoded_srp_verifier, &d_verifier, &d_salt));

	UASSERTEQ(size_t, d_verifier.size(), verifier.size());
	UASSERTEQ(size_t, d_salt.size(), salt.size());
	UASSERT(d_verifier == verifier);
	UASSERT(d_salt == salt);
}

bool TestSRP::testLoginWithPasswordAndVerifier(const std::string& verifier, const std::string& salt, const std::string& password_client, bool server_should_lie, u8* extra_state_data, size_t extra_state_len)
{
	// CLIENT => SERVER (TOSERVER_SRP_BYTES_A in MT protocol)
	std::string playername_u = lowercase(g_username);
	SRPUser* client_user = srp_user_new(SRP_SHA256, SRP_NG_2048,
		g_username.c_str(), playername_u.c_str(),
		(const unsigned char*)password_client.c_str(),
		password_client.length(), NULL, NULL);
	char* bytes_A = 0;
	size_t len_A = 0;
	SRP_Result res = srp_user_start_authentication(
		(struct SRPUser*)client_user, NULL, NULL, 0,
		(unsigned char**)&bytes_A, &len_A);
	UASSERT(res == SRP_OK);

	// SERVER => CLIENT (TOCLIENT_SRP_BYTES_S_B)
	char* bytes_B = 0;
	size_t len_B = 0;

	SRPVerifier* server_verifier = srp_verifier_new(SRP_SHA256, SRP_NG_2048,
		g_username.c_str(),
		(const unsigned char*)salt.c_str(), salt.size(),
		(const unsigned char*)verifier.c_str(), verifier.size(),
		(const unsigned char*)bytes_A, len_A,
		NULL, 0,
		(unsigned char**)&bytes_B, &len_B, NULL, NULL,
		extra_state_data, extra_state_len);

	UASSERT(bytes_B != NULL);

	// CLIENT => SERVER (TOSERVER_SRP_BYTES_M)

	char* bytes_M = 0;
	size_t len_M = 0;

	srp_user_process_challenge(client_user, (const unsigned char*)salt.c_str(), salt.size(),
		(const unsigned char*)bytes_B, len_B,
		(unsigned char**)&bytes_M, &len_M,
		extra_state_data, extra_state_len);

	UASSERT(bytes_M != NULL);
	UASSERTEQ(size_t, len_M, SHA256_DIGEST_LENGTH);

	// SERVER => CLIENT

	unsigned char* bytes_HAMK = nullptr;
	srp_verifier_verify_session(server_verifier,
		(unsigned char*)bytes_M, &bytes_HAMK);

	// if server_should_lie is set, we simulate the server not knowing the verifier value
	if (server_should_lie && bytes_HAMK)
	{
		for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
		{
			bytes_HAMK[i] = rand();
		}
	}

	if (!bytes_HAMK)
	{
		UASSERT(!srp_verifier_is_authenticated(server_verifier));

		srp_user_delete(client_user);
		srp_verifier_delete(server_verifier);
		return false;
	}
	else
	{
		UASSERT(srp_verifier_is_authenticated(server_verifier));

		srp_user_verify_session(client_user, bytes_HAMK);
		UASSERTEQ(bool, srp_user_is_authenticated(client_user), !server_should_lie);

		srp_user_delete(client_user);
		srp_verifier_delete(server_verifier);
		return true;
	}
}
