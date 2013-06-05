#define EOF (-1)
int unknown_int();

int scan_unknown_int(int *p)
{
  *p = unknown_int();
  return unknown_int();
}

int main()
{
  int n,i,m,j;
  while(scan_unknown_int(&n) != EOF)
    { 
      m=n;
      for(i=n-1;i>=1;i--)
      {   
        m=m*i;
        while(m%10==0)
        {
          m=m/10;
        }
        m=m%10000;
      }  
      m=m%10;
      printf("%5d -> %d\n",n,m);
    }
  return 0;
}
