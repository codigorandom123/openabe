/// 
/// Copyright (c) 2018 Zeutro, LLC. All rights reserved.
/// 
/// This file is part of Zeutro's OpenABE.
/// 
/// OpenABE is free software: you can redistribute it and/or modify
/// it under the terms of the GNU Affero General Public License as published by
/// the Free Software Foundation, either version 3 of the License, or
/// (at your option) any later version.
/// 
/// OpenABE is distributed in the hope that it will be useful,
/// but WITHOUT ANY WARRANTY; without even the implied warranty of
/// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
/// GNU Affero General Public License for more details.
/// 
/// You should have received a copy of the GNU Affero General Public
/// License along with OpenABE. If not, see <http://www.gnu.org/licenses/>.
/// 
/// You can be released from the requirements of the GNU Affero General
/// Public License and obtain additional features by purchasing a
/// commercial license. Buying such a license is mandatory if you
/// engage in commercial activities involving OpenABE that do not
/// comply with the open source requirements of the GNU Affero General
/// Public License. For more information on commerical licenses,
/// visit <http://www.zeutro.com>.
///
/// \brief Example use of the OpenABE API with CP-ABE
///

#include <iostream>
#include <string>
#include <cassert>
#include <openabe/openabe.h>
#include <openabe/zsymcrypto.h>

using namespace std;
using namespace oabe;
using namespace oabe::crypto;

int main(int argc, char **argv) {

InitializeOpenABE();

cout << "Testing CP-ABE context" << endl;
OpenABECryptoContext cpabe("CP-ABE");
string ct, pt1 = "hello world!", pt2;
cpabe.generateParams();

string access_policy = "Me or (Fi and P5) or (Fa and ((P5 and Cru) or (P5 and Ped) or (Cru and Ped)))";
string Bob = "|Me|P4|Cru|Pet";
string Charlie = "Fa|P4|Cru|Hem";
string Diana = "|Fa|P5|Ba|Ped";

//Bob
cout << "Bob consigue descifrar la información";
cpabe.keygen(Bob, "key_bob");
cpabe.encrypt(access_policy, pt1, ct);
bool result = cpabe.decrypt("key_bob", ct, pt2);
assert(result && pt1 == pt2);
cout << "Recovered message: " << pt2 << endl;

//Charlie
cout << "Charlie no consigue descifrar la información";
cpabe.keygen(Charlie, "key_charlie");
cpabe.encrypt(access_policy, pt1, ct);
result = cpabe.decrypt("key_charlie", ct, pt2);
assert(result && pt1 == pt2);
cout << "Recovered message: " << pt2 << endl;

//Diana
cout << "Diana consigue descifrar la información";
cpabe.keygen(Diana, "key_diana");
cpabe.encrypt(access_policy, pt1, ct);
result = cpabe.decrypt("key_diana", ct, pt2);
assert(result && pt1 == pt2);
cout << "Recovered message: " << pt2 << endl;

ShutdownOpenABE();

return 0;
}
