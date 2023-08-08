#include <cstdlib>
#include <verilated.h>
#include "Vdes_cracker.h"


int main(int argc, char *argv[]) {

  Verilated::commandArgs(argc, argv);
  auto tb = new Vdes_cracker;

  tb->rst = 1;
  for(int i = 0; i < 16; i++) {
    tb->clk = 1;
    tb->eval();
    tb->clk = 0;
    tb->eval();
  }
  tb->rst = 0;
  
  while(not(Verilated::gotFinish())) {
    tb->clk = 1;
    tb->eval();
    tb->clk = 0;
    tb->eval();
  };
  return 0;
}
