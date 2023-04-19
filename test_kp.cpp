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
OpenABECryptoContext kpabe("KP-ABE");
string ct, pt1 = "hello world!", pt2;
kpabe.generateParams();

string EV1 = "|GT|Alice|E8|Pub";
string EV2 = "|MC|Bob|E6|Pub";
string EV3 = "|MT|Alice|E5|Con";
string EV4 = "|GT|Bob|E4|Con";
string EV5 = "|MC|Alice|E9|Con";

string Director = "Pub or Con";
string Alice = "Alice or (Bob and Pub)";
string Bob = "Bob";

//Director
cout << "El director ha conseguido descifrar todas las evaluaciones \n";
kpabe.keygen(Director, "key_director");

kpabe.encrypt(EV1, pt1, ct);
bool result = kpabe.decrypt("key_director", ct, pt2);
assert(result && pt1 == pt2);
cout << "EV1 Recovered message: " << pt2 << endl;

kpabe.encrypt(EV2, pt1, ct);
result = kpabe.decrypt("key_director", ct, pt2);
assert(result && pt1 == pt2);
cout << "EV2 Recovered message: " << pt2 << endl;

kpabe.encrypt(EV3, pt1, ct);
result = kpabe.decrypt("key_director", ct, pt2);
assert(result && pt1 == pt2);
cout << "EV3 Recovered message: " << pt2 << endl;

kpabe.encrypt(EV4, pt1, ct);
result = kpabe.decrypt("key_director", ct, pt2);
assert(result && pt1 == pt2);
cout << "EV4 Recovered message: " << pt2 << endl;

kpabe.encrypt(EV5, pt1, ct);
result = kpabe.decrypt("key_director", ct, pt2);
assert(result && pt1 == pt2);
cout << "EV5 Recovered message: " << pt2 << endl;

//Alice
cout << "\n Alice ha conseguido descrifrar estas evaluaciones: EV1, EV2, EV3 y EV5 \n";
kpabe.keygen(Alice, "key_alice");

kpabe.encrypt(EV1, pt1, ct);
result = kpabe.decrypt("key_alice", ct, pt2);
assert(result && pt1 == pt2);
cout << "EV1 Recovered message: " << pt2 << endl;

kpabe.encrypt(EV2, pt1, ct);
result = kpabe.decrypt("key_alice", ct, pt2);
assert(result && pt1 == pt2);
cout << "EV2 Recovered message: " << pt2 << endl;

kpabe.encrypt(EV3, pt1, ct);
result = kpabe.decrypt("key_alice", ct, pt2);
assert(result && pt1 == pt2);
cout << "EV3 Recovered message: " << pt2 << endl;

kpabe.encrypt(EV4, pt1, ct);
result = kpabe.decrypt("key_alice", ct, pt2);
cout << "EV4 Could not recover the message \n";

kpabe.encrypt(EV5, pt1, ct);
result = kpabe.decrypt("key_alice", ct, pt2);
assert(result && pt1 == pt2);
cout << "EV5 Recovered message:" << pt2 << endl;

//Bob
cout << " \n Bob ha conseguido descifrar estas evaluaciones: EV2, EV4 \n";
kpabe.keygen(Bob, "key_bob");

kpabe.encrypt(EV1, pt1, ct);
result = kpabe.decrypt("key_bob", ct, pt2);
cout << "EV1 Could not recover the message \n";

kpabe.encrypt(EV2, pt1, ct);
result = kpabe.decrypt("key_bob", ct, pt2);
assert(result && pt1 == pt2);
cout << "EV2 Recovered message: " << pt2 << endl;

kpabe.encrypt(EV3, pt1, ct);
result = kpabe.decrypt("key_bob", ct, pt2);
cout << "EV3 Could not recover the message \n";

kpabe.encrypt(EV4, pt1, ct);
result = kpabe.decrypt("key_bob", ct, pt2);
assert(result && pt1 == pt2);
cout << "EV4 Recovered message: " << pt2 << endl;

kpabe.encrypt(EV5, pt1, ct);
result = kpabe.decrypt("key_bob", ct, pt2);
cout << "EV5 Could not recover the message \n \n";

ShutdownOpenABE();

return 0;
}
