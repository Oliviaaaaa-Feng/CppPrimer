#include <iostream>
#include <vector>
using namespace std;

void finalGrade(int grade){
    string result = (grade > 90) ? 
    "high pass" : (grade < 60) ? "fail" : "pass";
    cout << "your score is: " << result  << endl;
}

void numOfPass(int score[], int length) {
    int pass = 0, highPass = 0, fail = 0;
    for (int i = 0; i < length; i++) {
        int result = score[i];
        if (result > 90) {
            highPass += 1;
        }
        if (result < 60) {
            fail += 1;
        }
        if (result < 90 && result > 60) {
            pass += 1;
        }
    }
    cout << "highPass: " << highPass << endl;
    cout << "pass: " << pass << endl;
    cout << "fail: " << fail << endl;
    
}

int main(){
    //int i = 0;
    //int j;
    //j = ++i; 
    //j = i++;
    //cout << j << endl << i ;
    int score[] = { 50, 67, 98, 87, 59};
    int length = sizeof(score)/sizeof(score[0]);
    finalGrade(100);
    numOfPass(score,length);

 
    for( int *p = begin( score ); p != end( score ); p++ )
    {
        cout << score  << endl;
    }
 
    for( auto i : score )
    {
        cout << i << endl;
    }
 

    return 0;



    
}