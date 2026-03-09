#include <iostream>

using namespace std;

int main() {
    cout<<"Enter your name\n";
    string name;
    cin>>name;
    if (name=="admin") {
        cout << "Hello master\n";
        __builtin_trap();
    }
    cout << "Hello "<<name<<"\n";
    return 0;
}