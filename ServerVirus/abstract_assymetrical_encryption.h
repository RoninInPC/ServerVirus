#pragma once
#include<vector>
#include<string>

class AbstractAsymmetricalEncryption abstract {
public:
	virtual std::vector<std::pair<int, int>> Encode(const std::string& message);
	virtual std::string Decode(const std::vector<std::pair<int, int>>& message);
};