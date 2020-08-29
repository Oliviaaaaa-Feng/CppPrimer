#include <iostream>
using namespace std;

int main(){
    string s("some string");
    if (!s.empty()) // make sure there’s a character in s[0]
        s[0] = toupper(s[0]); // assign a new value to the first character in s
        int index != s.size() && !isspace(s[index])

    // notesasareferencetoconst;theelementsaren’tcopiedandcan’tbechanged 
    for (const auto &s : text) { // for each element in text
        cout << s; // print the current element
    // blank lines and those that end with a period get a newline 
        if (s.empty() || s[s.size() - 1] == ’.’)
            cout << endl;
        
        else
            cout << " "; // otherwise just separate with a space
    }
    if (!vec.empty())
        cout << vec[0];
}


