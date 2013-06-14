int setgid(int thing) {
    if (thing == 2) {
        return thing;
    } else {
        return thing - 1;
    }
}

int setuid(int thing) {
    if (thing == 2) {
        return thing;
    } else {
        return thing - 1;
    }
}

int main(int argc, char const* argv[])
{
    int AID_SHELL = argv[1];

    setgid(AID_SHELL);
    setuid(AID_SHELL);

    return 0;
}
