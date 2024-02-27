#pragma once
#include<ctime>
#include<stdlib.h>
#include<tuple>

class ElGamalGenerator {
private:
	int prime_;
	int second_key_;
	int third_key_;
	int private_key_;

private:
	static bool IsPrime(int number) {
		for (int i = 2; i < number / 2; i++) {
			if (number % i == 0) {
				return false;
			}
		}
		return true;
	}
public:
	ElGamalGenerator(int prime, int second_key, int private_key, bool change_private = false) {
		if (IsPrime(prime)) {
			prime_ = prime;
		}
		else {
			prime_ = GeneratePrimeNumber();
		}
		if (prime > second_key) {
			second_key_ = second_key;
		}
		else {
			second_key_ = GenerateLessNumber(prime_);
		}
		if (change_private or prime > private_key) {
			private_key_ = private_key;
		}
		else {
			private_key_ = GenerateLessNumber(prime_);
		}
		third_key_ = PowerMod(second_key_, private_key_, prime);
	}

	static int PowerMod(int a, int b, int mod) {
		int ans = 1;
		for (int i = 0; i < b; i++) {
			ans *= a % mod;
		}
		return ans;
	}
	static int MulMod(int a, int b, int mod) {
		return a * b % mod;
	}

	static int GeneratePrimeNumber(int mod = 1000) {
		srand(time(NULL));
		while (true) {
			int i = rand() % mod;
			if (IsPrime(i))
				return i;
		}
		return -1;
	}
	static int GenerateLessNumber(int less_number, int mod = 1000) {
		srand(time(NULL));
		while (true) {
			int i = rand() % mod;
			if (i < less_number)
				return i;
		}
		return -1;
	}
	std::tuple<int, int, int> GetPublicKey() {
		return std::make_tuple(prime_, second_key_, third_key_);
	}
	int GetPrivateKey() {
		return private_key_;
	}
};