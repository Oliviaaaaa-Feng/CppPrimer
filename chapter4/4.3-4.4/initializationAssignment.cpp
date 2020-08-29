#include <iostream>
#include <vector>
using namespace std;



//void get_value(vector<int> vs){
   // for (int i = 0; i < vs.size(); i++) { 
     //   int value = vs[i];
    //{
//}


int main(){
    int i = 0, j = 0, k = 0; // initializations, not assignment 
    const int ci = i; // initialization, not assignment
    k = 3;
    cout << k << endl;
    int sum = 0; // sumvaluesfrom1through10inclusive
    for (int val = 1; val <= 10; ++val){
        sum += val; // equivalenttosum=sum+val
        cout << sum << endl;
    }
    return 0;
}