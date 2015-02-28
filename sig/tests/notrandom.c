void randombytes(unsigned char *x,unsigned long long xlen)
{
  int i;
  for(i=0;i<xlen;i++) x[i] = i & 0xff;
}
