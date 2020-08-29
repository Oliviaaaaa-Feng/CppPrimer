#include <iostream>
using namespace std;

int main(){
    int ival1 = 21/6; // ival1 is 3; result is truncated; remainder is discarded 
    int ival2 = 21/7; // ival2 is 3; no remainder; result is an integral value
    cout << ival1 << endl;
    cout << ival2 << endl;
    int ival3 = 42; 
    double dval = 3.14;
    float ival4 = ival3 % 12;   // ok: result is 6
    //ival % dval;  error: floating-point operand
    cout << ival4 << endl;
    return 0;
}

