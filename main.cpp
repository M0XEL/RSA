#include <string>
#include <iostream>
#include <stdlib.h>
#include <math.h>
#include <chrono>

struct KeyTupel {
	int component_0;
	int component_1;
};

struct Message {
	std::string string;
	int signature;
};

inline int generateKey()
{
	//using namespace std::chrono;
	//int timestamp = duration_cast<microseconds>(system_clock::now().time_since_epoch()).count();
	//std::hash<int> hasher;
	//return hasher(timestamp);

	srand(time(nullptr));
	return rand();
}

Message encryptMessageXor(int key, Message message)
{
	for (int i = 0; i < message.string.size(); i++)
		message.string[i] ^= key;

	return message;
}

size_t hashMessage(Message message)
{
	std::hash<std::string> hasher;
	return hasher(message.string);
}

struct Entity
{
	int private_key;
	int shared_key;
	Message message;

	void generatePrivateKey()
	{
		private_key = generateKey();
	}

	int createPuplicKeyPair(KeyTupel public_key)
	{
		return ((int)pow(public_key.component_0, private_key)) % public_key.component_1;
	}

	void createSharedKey(int public_key_pair, int public_key_component_1)
	{
		shared_key = ((int)pow(public_key_pair, private_key)) % public_key_component_1;
	}

	void signateMessage(size_t hash)
	{
		message.signature = hash + shared_key; // TODO
	}

	size_t designateMessage()
	{
		return message.signature - shared_key; // TODO
	}

	void show()
	{
		std::cout << "#####################################" << std::endl;
		std::cout << "Private Key       |" << private_key << std::endl;
		std::cout << "Shared Key        |" << shared_key << std::endl;
		std::cout << "Message String    |" << message.string << std::endl;
		std::cout << "Message Signature |" << message.signature << std::endl;
		std::cout << "#####################################\n" << std::endl;
	}
};

bool compareHashes(Message message, Entity user)
{
	if (hashMessage(message) == user.designateMessage()) {
		return true;
	}
	else {
		return false;
	}
}

int main()
{
	Entity user_0;
	user_0.generatePrivateKey();

	Entity user_1;
	user_1.generatePrivateKey();

	KeyTupel public_key;
	public_key.component_0 = generateKey();
	public_key.component_1 = generateKey();

	KeyTupel public_key_pair;
	public_key_pair.component_0 = user_0.createPuplicKeyPair(public_key);
	public_key_pair.component_1 = user_1.createPuplicKeyPair(public_key);

	user_0.createSharedKey(public_key_pair.component_1, public_key.component_1);
	user_1.createSharedKey(public_key_pair.component_0, public_key.component_1);

	user_0.message.string = "Hello World!";

	Message secret_message;
	secret_message = encryptMessageXor(user_0.shared_key, user_0.message);
	size_t message_hash = hashMessage(secret_message);
	user_0.signateMessage(message_hash);
	secret_message.signature = user_0.message.signature;

	//secret_message.string = "Hacked!";
	//secret_message.signature = 123;

	user_1.message = encryptMessageXor(user_1.shared_key, secret_message);

	std::cout << "#####################################" << std::endl;
	std::cout << "Puplic Key(s)   |" << public_key.component_0 << ", " << public_key.component_1 << std::endl;
	std::cout << "Public Key Pair |" << public_key_pair.component_0 << ", " << public_key_pair.component_1 << std::endl;
	std::cout << "#####################################\n" << std::endl;

	user_0.show();

	std::cout << "#####################################" << std::endl;
	std::cout << "Encrypted Message String |" << secret_message.string << std::endl;
	std::cout << "Encrypted Message Signature |" << secret_message.signature << std::endl;
	std::cout << "#####################################\n" << std::endl;

	user_1.show();

	if (!compareHashes(secret_message, user_1))
		std::cout << "Data corrupted!" << std::endl;

	getchar();
	return 0;
}