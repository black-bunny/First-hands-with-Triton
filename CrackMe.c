#include <stdio.h>
#include <stdlib.h>


int main(int argc, char *argv[]) {
  int x = 2;
  int y = 6;
  int errors = 0;

  unsigned char pass_val1 = (argv[1][0] - argv[1][10]);
  unsigned char pass_val2 = (argv[1][1] - argv[1][9]);
  unsigned char pass_val3 = (argv[1][2] - argv[1][8]);
  unsigned char pass_val4 = (argv[1][3] - argv[1][7]);
  unsigned char pass_val5 = (argv[1][4] - argv[1][6]);
  unsigned char pass_val6 = (argv[1][9] - argv[1][5]);

  if (argc != 2)
  {
    printf("Usage: %s password\n");
    exit(1);
  }

  if ((pass_val2 - pass_val4) == 0 )
    exit(1);
  if ((pass_val1 - pass_val5) == 0 )
    exit(1);
  if (pass_val3 - pass_val6 != 161)
    exit(1);

  if(((pass_val6 ^ pass_val1) != x))
    errors++;

  if (((pass_val5 ^ pass_val2) + (29 - (7 + 5)) -x) != pass_val5+10) 
    errors++;

  if(((pass_val4 ^ pass_val3) + pass_val4) != pass_val3+2)
    errors++;

  if (((pass_val6 ^ pass_val4) + pass_val4) != pass_val6)
    errors++;

  if((argv[1][4] ^ pass_val1) != (48^31)) 
    errors++;

  if ((errors) == (pass_val5 - pass_val3 - pass_val1)/2)
    errors++;

  if(argv[1][7]*2 != pass_val5)
    errors++;

  if (((pass_val6 - (pass_val4 + x *(pass_val2 - pass_val4))) * (x * pass_val4) + 22) != pass_val5)
    errors++;

  if ((y * pass_val1 + (pass_val2 - pass_val4) +2) != pass_val3)
    errors++;

  if ((pass_val3 - y * (pass_val4) / (pass_val2 - pass_val4) - (pass_val1-pass_val6)/2) != 174)
    errors++;

  if (((pass_val3 - argv[1][errors]) + x) == argv[1][5])
    errors++;

  if ((((~((argv[1][0]<<1)&0xFF))&0xFF) + errors -1 != 0x58 ) || ((~((argv[1][errors]<<1)&0xFF))&0xFF) + 3*errors - 3 != 192)
    exit(1);

  printf("Good password!!!!\n");
}
