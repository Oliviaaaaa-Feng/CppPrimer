#include <iostream>
using namespace std;

int main(){
    int i = 1024;
    int k = -i;      // i is -1024
    bool b = true;
    bool b2 = -b;    // b2 is true!

    cout << i << endl; // print the element
    cout << k << endl;
    cout << b << endl;
    cout << b2 << endl;
    return 0;
}

