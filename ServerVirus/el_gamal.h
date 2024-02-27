#pragma once
#include<sstream>
#include<tuple>
#include<iostream>



#include "abstract_asymmetrical_encryption.h"
#include "el_gamal_generator.h"
class ElGamal : public AbstractAsymmetricalEncryption {

private:
	ElGamalGenerator* el_gamal_generator_;

public:
	ElGamal(int prime, int public_key, int private_key) {
		el_gamal_generator_ = new ElGamalGenerator(prime, public_key, private_key);
	}
	std::vector<std::pair<int, int>> Encode(const std::string& message) {
		int prime = std::get<0>(el_gamal_generator_->GetPublicKey());
		int second = std::get<1>(el_gamal_generator_->GetPublicKey());
		int third = std::get<2>(el_gamal_generator_->GetPublicKey());

		std::vector<std::pair<int, int>> answer = {};
		for (char c : message) {
			int random = ElGamalGenerator::GenerateLessNumber(1000, prime - 2) + 1;
			int a = ElGamalGenerator::PowerMod(second, random, prime);
			int b = ElGamalGenerator::MulMod(ElGamalGenerator::PowerMod(third, random, prime), static_cast<int>(c), prime);
			answer.push_back({ a,b });
		}
		return answer;
	}

	std::string Decode(const std::vector<std::pair<int, int>>& message) {
		int prime = std::get<0>(el_gamal_generator_->GetPublicKey());
		int private_key = el_gamal_generator_->GetPrivateKey();

		std::string answer;
		for (auto pair : message) {
			int a = pair.first;
			int b = pair.second;
			if (a == 0 or b == 0)
				throw std::logic_error("Incorrect a or b in algorithm");
			int c = ElGamalGenerator::MulMod(b, ElGamalGenerator::PowerMod(a, prime - 1 - private_key, prime), prime);
			answer += static_cast<char>(c);
		}
		return answer;
	}
};

std::vector<std::pair<int, int>> ToArrayPair(std::string message) {
	std::vector<std::pair<int, int>> answer = {};
	std::string a, b;
	std::stringstream ss(message);
	while (ss >> a) {
		ss >> b;
		answer.push_back({ stoi(a),stoi(b) });
	}
	return answer;
}

std::string ToString(const std::vector<std::pair<int, int>>& message) {
	std::string answer;
	for (auto part : message) {
		answer += std::to_string(part.first) + " " + std::to_string(part.second) + " ";
	}
	return answer;
}