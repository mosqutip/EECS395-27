#include <cstdio>

class Ex {
    public:
        int x;
        int y;
        int fun1(int arg1, int arg2);
        Ex(int,int);

    protected:
        int x_prot;
        int y_prot;
        int fun2(int arg1, int arg2);

    private:
        int x_priv;
        int y_priv;
        int fun3(int arg1, int arg2);
};

int Ex::fun1(int arg1, int arg2) {
    return y * arg1 + y* arg2;
}

int Ex::fun2(int arg1, int arg2) {
    return y_prot * arg1 - y_prot* arg2;
}

int Ex::fun3(int arg1, int arg2) {
    return y_priv * arg1 + y_priv* arg2;
}

Ex::Ex(int a, int b) {
    x = a;
    y = b;
    x_prot = a-12;
    y_prot = b-12;
    x_priv = a*3;
    y_priv = b*3;
}

int main(int argc, char const* argv[])
{
    Ex a (4,-19);

    std::printf("a has publics [%d,%d]\n",a.x,a.y);
    return 0;
}
