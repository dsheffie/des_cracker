UNAME_S = $(shell uname -s)

OBJ = top.o verilated.o

V_SRC = des_cracker.v

ifeq ($(UNAME_S),Linux)
	CXX = clang++-12 -flto
	MAKE = make
	VERILATOR_SRC = /home/dsheffie/local/share/verilator/include/verilated.cpp
	VERILATOR_VCD = /home/dsheffie/local/share/verilator/include/verilated_vcd_c.cpp
	VERILATOR_INC = /home/dsheffie/local/share/verilator/include
	VERILATOR_DPI_INC = /home/dsheffie/local/share/verilator/include/vltstd/
	VERILATOR = /home/dsheffie/local/bin/verilator
endif


OPT = -O3 -g -std=c++14
CXXFLAGS = -std=c++11 -g  $(OPT) -I$(VERILATOR_INC) -I$(VERILATOR_DPI_INC)
LIBS = -lpthread

DEP = $(OBJ:.o=.d)

EXE = des

.PHONY : all clean

all: $(EXE)

$(EXE) : $(OBJ) obj_dir/Vdes_cracker__ALL.a
	$(CXX) $(CXXFLAGS) $(OBJ) obj_dir/*.o $(LIBS) -o $(EXE)

top.o: top.cc obj_dir/Vdes_cracker__ALL.a
	$(CXX) -MMD $(CXXFLAGS) -Iobj_dir -c $< 

verilated.o: $(VERILATOR_SRC)
	$(CXX) -MMD $(CXXFLAGS) -c $< 

obj_dir/Vdes_cracker__ALL.a : des_cracker.v
	$(VERILATOR) -cc des_cracker.v
	$(MAKE) OPT_FAST="-O3 -flto" -C obj_dir -f Vdes_cracker.mk

-include $(DEP)



clean:
	rm -rf $(EXE) $(OBJ) $(DEP) obj_dir
