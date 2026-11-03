#include <iostream>
#include <string>
#include <vector>
int main() {
    std::vector<std::string> v{"hello", "from", "C++"};
    std::string s;
    for (const auto &w : v) s += (s.empty() ? "" : " ") + w;
    std::cout << s << std::endl;
    return 0;
}
