module des_cracker(input clk, input rst);
   wire [63:0] w_plain = 64'h0123456789abcdef;
   wire [63:0] w_cipher = 64'h85e813540f0ab405;
   wire [63:0] w_key;
   wire        w_done;

   wire [63:0] w_start = 64'h133457799B000000;
   
   //Instantiate the Unit Under Test (UUT)
   top #(.NUM_PEs(1)) uut(
	   // Outputs
	   .found			(w_done),
	   .key				(w_key),
	   // Inputs
	   .clk				(clk),
	   .rst				(rst),
	   .startkey                    (w_start),
	   .plaintext			(w_plain),
	   .ciphertext			(w_cipher)
	   );
   

   reg [31:0]  r_ticks;
   always@(posedge clk)
     begin
	r_ticks <= rst ? 'd0 : (r_ticks + 'd1);
     end
   
   wire [63:0] w_a = 64'h133457799BBCDFF1;
   always@(posedge clk)
     begin
	if(w_done)
	  begin
	     $display("k = %h", w_key);
	     $display("a = %h", w_a);
	     $display("d = %b", w_key ^ w_a);
	     $display("ticks = %d", r_ticks);
	     
	     $finish();
	  end
     end
   
endmodule

module addkeyparity(/*AUTOARG*/
   // Outputs
   key64_out,
   // Inputs
   key56_in
   );
   parameter XOR = 0;
   input [55:0] key56_in;
   output [63:0] key64_out;

   genvar 	 i,j;

   generate
      for(i=0;i<8;i=i+1)
	begin: outer_loop
	   for(j=0;j<7;j=j+1)
	     begin: inner_loop
		assign key64_out[i*8+j+1] = key56_in[i*7+j];
	     end
	   if(XOR==1)
	     begin
		assign key64_out[i*8] = ~(^key56_in[((i+1)*7-1):i*7]);
	     end
	   else
	     begin
		assign key64_out[i*8] = 1'b0;
	     end
	end
   endgenerate
endmodule // dropkeyparity


module cracker(/*AUTOARG*/
   // Outputs
   key_out, found_out,
   // Inputs
   clk, rst, startkey, plaintext, ciphertext, key_in, found_in
   );
   input clk;
   input rst;
   input [55:0] startkey;
   input [63:0] plaintext;
   input [63:0] ciphertext;
   input [55:0] key_in;
   input 	found_in;
   
   output [55:0] key_out;
   output found_out;
   
   parameter ID = 0 ;
   parameter NUM_PEs = 1;
   
   wire [63:0] w_ciphertext;
   wire        w_done;

   reg [55:0] r_key;
   reg 	      t_decr, t_start;

   reg [2:0]  r_state, n_state;
   reg [4:0]  r_cnt, n_cnt;
   reg 	      r_found, n_found;
   reg 	      r_found_out;
   reg [55:0] r_key_out;

   assign found_out = r_found_out;
   assign key_out = r_key_out;
   
   always@(posedge clk)
     begin
	if(rst)
	  begin
	     r_state <= 'd0;
	     r_cnt <= 'd0;
	     r_found <= 1'b0;
	  end
	else
	  begin
	     r_state <= n_state;
	     r_cnt <= n_cnt;
	     r_found <= n_found;
	  end
     end

   
   always@(posedge clk)
     begin
	if(rst)
	  begin
	     r_found_out <= 'd0;
	     r_key_out <= 'd0;
	  end
	else
	  begin
	     r_found_out <= r_found ? 1'b1 : found_in;
	     r_key_out <= r_found ? r_key : key_in;
	  end
     end
   
   always@(posedge clk)
     begin
	if(rst)
	  begin
	     r_key <= startkey | ID;
	  end
	else
	  begin
	     if(t_start)
	       begin
		  r_key <= r_key + NUM_PEs;
	       end
	     else if(t_decr)
	       begin
		  r_key <= r_key - NUM_PEs;
	       end
	  end
     end // always@ (posedge clk)

   wire w_match = (w_ciphertext==ciphertext)&w_done;
      
   always@(*)
     begin
	n_state = r_state;
	n_cnt = r_cnt;
	n_found = 1'b0;
	t_decr = 1'b0;
	t_start = 1'b0;
	case(r_state)
	  3'd0:
	    begin
	       t_start = 1'b1;
	       n_state = 3'd1;
	    end
	  3'd1:
	    begin
	       if(w_match)
		 begin
		    $display("PE %d found key!", ID);
		    n_state = 3'd2;
		    n_cnt = 'd0;
		 end
	       else if(found_in)
		 begin
		    n_state = 3'd4;
		 end
	       else
		 begin
		    t_start = 1'b1;
		 end
	    end
	  3'd2:
	    begin
	       t_decr = 1'b1;
	       n_cnt = r_cnt + 'd1;
	       //$display("PE %d, r_key = %x", ID, r_key);
	       if(r_cnt == 'd15)
		 begin
		    n_state = 'd3;
		    n_found = 1'b1;
		 end
	       /* wait pipeline depth */
	    end
	  3'd3:
	    begin
	       n_found = 1'b1;
	    end
	  3'd4:
	    begin
	       
	    end
	  default:
	    begin
	       n_state = 'd0;
	    end
	endcase
     end // always@ (*)


   wire [63:0] 	 w_key64;
   addkeyparity a (
		   .key64_out		(w_key64),
		   .key56_in		(r_key)
		   );
      
   f_tree #(.ID(ID)) m(
	    // Outputs
	    .ciphertext			(w_ciphertext),
	    .done			(w_done),
	    // Inputs
	    .clk			(clk),
	    .rst			(rst),
	    .encrypt			(1'b1),
	    .start			(t_start),
	    .plaintext			(plaintext),
	    .key			(w_key64)
	    );
   
   
endmodule // cracker
module dropkeyparity(/*AUTOARG*/
   // Outputs
   key56_out,
   // Inputs
   key64_in
   );
   input [63:0] key64_in;
   output [55:0] key56_out;

   genvar 	 i,j;

   generate
      for(i=0;i<8;i=i+1)
	begin: outer_loop
	   for(j=0;j<7;j=j+1)
	     begin: inner_loop
		assign key56_out[i*7+j] = key64_in[i*8+j+1];
	     end
	end
   endgenerate
endmodule // dropkeyparity


module e(in, out);
 input [31:0] in;
 output [47:0] out;

assign out[0] = in[31];
assign out[1] = in[0];
assign out[2] = in[1];
assign out[3] = in[2];
assign out[4] = in[3];
assign out[5] = in[4];

assign out[6] = in[3];
assign out[7] = in[4];
assign out[8] = in[5];
assign out[9] = in[6];
assign out[10] = in[7];
assign out[11] = in[8];

assign out[12] = in[7];
assign out[13] = in[8];
assign out[14] = in[9];
assign out[15] = in[10];
assign out[16] = in[11];
assign out[17] = in[12];

assign out[18] = in[11];
assign out[19] = in[12];
assign out[20] = in[13];
assign out[21] = in[14];
assign out[22] = in[15];
assign out[23] = in[16];

assign out[24] = in[15];
assign out[25] = in[16];
assign out[26] = in[17];
assign out[27] = in[18];
assign out[28] = in[19];
assign out[29] = in[20];

assign out[30] = in[19];
assign out[31] = in[20];
assign out[32] = in[21];
assign out[33] = in[22];
assign out[34] = in[23];
assign out[35] = in[24];

assign out[36] = in[23];
assign out[37] = in[24];
assign out[38] = in[25];
assign out[39] = in[26];
assign out[40] = in[27];
assign out[41] = in[28];

assign out[42] = in[27];
assign out[43] = in[28];
assign out[44] = in[29];
assign out[45] = in[30];
assign out[46] = in[31];
assign out[47] = in[0];

endmodule
module feistel(half_block, subkey, out);
  input [31:0] half_block;
  input [47:0] subkey;
  output [31:0] out;

  wire [3:0] so_0, so_1, so_2, so_3, so_4, so_5, so_6, so_7;
  wire [47:0] e_key, xor_result;

  wire [5:0] s0_addr, s1_addr, s2_addr, s3_addr, s4_addr, s5_addr, s6_addr, s7_addr;  assign s7_addr = xor_result[5:0];
  assign s6_addr = xor_result[11:6];
  assign s5_addr = xor_result[17:12];
  assign s4_addr = xor_result[23:18];
  assign s3_addr = xor_result[29:24];
  assign s2_addr = xor_result[35:30];
  assign s1_addr = xor_result[41:36];
  assign s0_addr = xor_result[47:42];

e expand(
  .in(half_block),
  .out(e_key)
);
 
 // always@(half_block or e_key)
 // $display("half_block = %b, e_key = %b", half_block, e_key);

 assign xor_result = e_key ^ subkey;

 //always@(subkey or e_key or xor_result)
 // $display("subkey = %b, xor_result = %b", subkey, xor_result);

s1 sbox0(
 .stage1_input(s0_addr),
 .stage1_output(so_0)
);

s2 sbox1(
 .stage1_input(s1_addr),
 .stage1_output(so_1)
);

s3 sbox2(
 .stage1_input(s2_addr),
 .stage1_output(so_2)
);

s4 sbox3(
 .stage1_input(s3_addr),
 .stage1_output(so_3)
);

s5 sbox4(
 .stage1_input(s4_addr),
 .stage1_output(so_4)
);

s6 sbox5(
 .stage1_input(s5_addr),
 .stage1_output(so_5)
);

s7 sbox6(
 .stage1_input(s6_addr),
 .stage1_output(so_6)
);

s8 sbox7(
 .stage1_input(s7_addr),
 .stage1_output(so_7)
);

p per(
 .in({so_0,so_1,so_2,so_3,so_4,so_5,so_6,so_7}),
 .out(out)
);

endmodule
module f_tree(/*AUTOARG*/
   // Outputs
   ciphertext, done,
   // Inputs
   clk, rst, encrypt, start, plaintext, key
   );
   output [63:0] ciphertext;
   output 	 done;
   
   input 	 clk;
   input 	 rst;
   input 	 encrypt;
   input 	 start;
      
   input [63:0]  plaintext;
   input [63:0]  key;
   
   
   wire [31:0] 	 ip_l, ip_r;
   wire [31:0] 	 out_l [15:0];
   wire [31:0] 	 out_r [15:0];
   
   wire 	 valid[15:0];
   wire [55:0] 	 w_subkey[15:0];
   parameter ID = 0;
   assign done = valid[15];

   
   genvar 	 i;

   wire [55:0] 	 w_pc1_subkey;
   pc1 pc1_keygen (
		   .in(key), 
		   .out(w_pc1_subkey)
		   );
   
   wire [63:0] 	 w_ip;

   assign ip_l = w_ip[63:32];
   assign ip_r = w_ip[31:0];
   
   ip ip0(
	  .in(plaintext),
	  .out(w_ip)
	  );
   
   wire [27:0] w0 = {w_pc1_subkey[26:0],w_pc1_subkey[27]};
   wire [27:0] w1 = {w_pc1_subkey[54:28],w_pc1_subkey[55]};
     

   wire [55:0] w_init_subkey = encrypt ? {w_pc1_subkey[27:0],w_pc1_subkey[55:28]} : {w0,w1};
   
   generate
      for(i=0;i<16;i=i+1)
	begin : des_network
	   if(i==0)
	     begin
		f_xor #(.STAGE(i)) m0(
				      .clk(clk), 
				      .rst(rst),
				      .encrypt(encrypt),
				      .valid_in(start),
				      .subkey_shiftamt((i==0) ? 2'd1 : (i==1) ? 2'd1 :  (i==8) ? 2'd1 : (i==15) ? 2'd1 :  2'd2),
				      .in_l(ip_l), 
				      .in_r(ip_r),
				      .subkey_in(w_init_subkey),
				      .out_l(out_l[i]), 
				      .out_r(out_r[i]),
				      .subkey_out(w_subkey[i]),
				      .valid_out(valid[i])
				      );
	     end
	   else
	     begin
		f_xor #(.STAGE(i)) mm(
				      .clk(clk), 
				      .rst(rst),
				      .encrypt(encrypt),
				      .valid_in(valid[i-1]),
				      .subkey_shiftamt((i==0) ? 2'd1 : (i==1) ? 2'd1 :  (i==8) ? 2'd1 : (i==15) ? 2'd1 :  2'd2),
				      .in_l(out_l[i-1]), 
				      .in_r(out_r[i-1]),
				      .subkey_in(w_subkey[i-1]),
				      .out_l(out_l[i]), 
				      .out_r(out_r[i]),
				      .subkey_out(w_subkey[i]),
				      .valid_out(valid[i])
				      ); 
	     end
	end
   endgenerate
   
   ip_inv ip_inv0 (
		   .in({out_r[15],out_l[15]}),
		   .out(ciphertext)
		   );
   
endmodule
module f_xor(/*AUTOARG*/
   // Outputs
   subkey_out, out_l, out_r, valid_out,
   // Inputs
   clk, rst, valid_in, encrypt, subkey_shiftamt, in_l, in_r,
   subkey_in
   );
   parameter STAGE = -1;
   input clk;
   input rst;
   input valid_in;
   input encrypt;
   input [1:0] subkey_shiftamt;
   
   input [31:0] in_l;
   input [31:0] in_r;
   
   input [55:0] subkey_in;
   output [55:0] subkey_out;
   output [31:0] out_l;
   output [31:0] out_r;
   output 	 valid_out;
   
   reg [31:0] 	 out_l, out_r;
   reg 		 r_val;
   wire [31:0] 	 f_out;
   
   reg [55:0] 	 r_subkey;
   
   wire [27:0] 	 w_c0 = subkey_in[27:0];
   wire [27:0] 	 w_d0 = subkey_in[55:28];

   
   wire [27:0] 	 w_d0_lshift = (subkey_shiftamt==2'd1) ? {w_c0[26:0], w_c0[27]} : {w_c0[25:0], w_c0[27:26]};
   wire [27:0] 	 w_c0_lshift = (subkey_shiftamt==2'd1) ? {w_d0[26:0], w_d0[27]} : {w_d0[25:0], w_d0[27:26]};
   wire [55:0] 	 w_subkey_lshift = {w_d0_lshift,w_c0_lshift};
   
   wire [27:0] 	 w_d0_rshift = (subkey_shiftamt==2'd1) ? {w_c0[0], w_c0[27:1]} : {w_c0[1:0], w_c0[27:2]};
   wire [27:0] 	 w_c0_rshift = (subkey_shiftamt==2'd1) ? {w_d0[0], w_d0[27:1]} : {w_d0[1:0], w_d0[27:2]};
   wire [55:0] 	 w_subkey_rshift = {w_d0_rshift,w_c0_rshift};

   wire [55:0] 	 w_subkey_shift = encrypt ? w_subkey_lshift: w_subkey_rshift;

   wire [47:0] 	 w_subkey;
   
   pc2 subkey_gen (
		   .in(w_subkey_shift), 
		   .out(w_subkey)
		   );
   
   assign valid_out = r_val;
   assign subkey_out = r_subkey;

   
/*   
   always@(posedge clk)
     begin
	if(valid_in)
	  begin
	     $display("STAGE=%d : h=%b => %b,%b,%b,%b,%b,%b,%b,%b\n", 
		      STAGE, 
		      w_subkey_shift,
		      w_subkey[47:42],
		      w_subkey[41:36],
		      w_subkey[35:30],
		      w_subkey[29:24],
		      w_subkey[23:18],
		      w_subkey[17:12],
		      w_subkey[11:6],
		      w_subkey[5:0]
		      );
	  
	  end
     end 
 */
   
   
   always@(posedge clk)
     begin
	if(rst)
	  begin
	     out_l <= 32'd0;
	     out_r <= 32'd0;
	     r_val <= 1'b0;
	     r_subkey <= 'd0;
	  end
	else
	  begin
	     out_l <= in_r;
	     out_r <= in_l ^ f_out;
	     r_val <= valid_in;
	     r_subkey <= encrypt ? {w_c0_lshift,w_d0_lshift} : {w_c0_rshift,w_d0_rshift};
	  end
     end	
   
   feistel f(
	     .half_block(in_r),
	     .subkey(w_subkey),
	     .out(f_out)
	     );

endmodule // f_xor

module ip_inv(in, out);
   input [63:0] in;
   output [63:0] out;

   assign out[0] = in[39];
   assign out[1] = in[7];
   assign out[2] = in[47];
   assign out[3] = in[15];
   assign out[4] = in[55];
   assign out[5] = in[23];
   assign out[6] = in[63];
   assign out[7] = in[31];

   assign out[8] = in[38];
   assign out[9] = in[6];
   assign out[10] = in[46];
   assign out[11] = in[14];
   assign out[12] = in[54];
   assign out[13] = in[22];
   assign out[14] = in[62];
   assign out[15] = in[30];

   assign out[16] = in[37];
   assign out[17] = in[5];
   assign out[18] = in[45];
   assign out[19] = in[13];
   assign out[20] = in[53];
   assign out[21] = in[21];
   assign out[22] = in[61];
   assign out[23] = in[29];

   assign out[24] = in[36];
   assign out[25] = in[4];
   assign out[26] = in[44];
   assign out[27] = in[12];
   assign out[28] = in[52];
   assign out[29] = in[20];
   assign out[30] = in[60];
   assign out[31] = in[28];

   assign out[32] = in[35];
   assign out[33] = in[3];
   assign out[34] = in[43];
   assign out[35] = in[11];
   assign out[36] = in[51];
   assign out[37] = in[19];
   assign out[38] = in[59];
   assign out[39] = in[27];

   assign out[40] = in[34];
   assign out[41] = in[2];
   assign out[42] = in[42];
   assign out[43] = in[10];
   assign out[44] = in[50];
   assign out[45] = in[18];
   assign out[46] = in[58];
   assign out[47] = in[26];

   assign out[48] = in[33];
   assign out[49] = in[1];
   assign out[50] = in[41];
   assign out[51] = in[9];
   assign out[52] = in[49];
   assign out[53] = in[17];
   assign out[54] = in[57];
   assign out[55] = in[25];

   assign out[56] = in[32];
   assign out[57] = in[0];
   assign out[58] = in[40];
   assign out[59] = in[8];
   assign out[60] = in[48];
   assign out[61] = in[16];
   assign out[62] = in[56];
   assign out[63] = in[24];  
   


endmodule
module ip(in, out);
   input [63:0] in;
   output [63:0] out;
   
   assign out[0] = in[57];
   assign out[1] = in[49];
   assign out[2] = in[41];
   assign out[3] = in[33];
   assign out[4] = in[25];
   assign out[5] = in[17];
   assign out[6] = in[9];
   assign out[7] = in[1];
   
   assign out[8] = in[59];
   assign out[9] = in[51];
   assign out[10] = in[43];
   assign out[11] = in[35];
   assign out[12] = in[27];
   assign out[13] = in[19];
   assign out[14] = in[11];
   assign out[15] = in[3];

   assign out[16] = in[61];
   assign out[17] = in[53];
   assign out[18] = in[45];
   assign out[19] = in[37];
   assign out[20] = in[29];
   assign out[21] = in[21];
   assign out[22] = in[13];
   assign out[23] = in[5];

   assign out[24] = in[63];
   assign out[25] = in[55];
   assign out[26] = in[47];
   assign out[27] = in[39];
   assign out[28] = in[31];
   assign out[29] = in[23];
   assign out[30] = in[15];
   assign out[31] = in[7];

   assign out[32] = in[56];
   assign out[33] = in[48];
   assign out[34] = in[40];
   assign out[35] = in[32];
   assign out[36] = in[24];
   assign out[37] = in[16];
   assign out[38] = in[8];
   assign out[39] = in[0];

   assign out[40] = in[58];
   assign out[41] = in[50];
   assign out[42] = in[42];
   assign out[43] = in[34];
   assign out[44] = in[26];
   assign out[45] = in[18];
   assign out[46] = in[10];
   assign out[47] = in[2];

   assign out[48] = in[60];
   assign out[49] = in[52];
   assign out[50] = in[44];
   assign out[51] = in[36];
   assign out[52] = in[28];
   assign out[53] = in[20];
   assign out[54] = in[12];
   assign out[55] = in[4];
   assign out[56] = in[62];
   assign out[57] = in[54];
   assign out[58] = in[46];
   assign out[59] = in[38];
   assign out[60] = in[30];
   assign out[61] = in[22];
   assign out[62] = in[14];
   assign out[63] = in[6];  
   


endmodule
module pc1(in,out);
   input [63:0] in;
   output [55:0] out;

   genvar 	 i;
   wire [63:0] 	 w_in;
   wire [55:0] 	 w_out;
   
   generate
      for(i=0;i<64;i=i+1)
	begin : in_swapper
	   assign w_in[i] = in[63-i];
	end
   endgenerate


   generate
      for(i=0;i<56;i=i+1)
	begin : out_swapper
	   assign out[i] = w_out[55-i];
	end
   endgenerate
   
   
   assign w_out[0] = w_in[56];
   assign w_out[1] = w_in[48];
   assign w_out[2] = w_in[40];
   assign w_out[3] = w_in[32];
   assign w_out[4] = w_in[24];
   assign w_out[5] = w_in[16];
   assign w_out[6] = w_in[8];
   
   assign w_out[7] = w_in[0];
   assign w_out[8] = w_in[57];
   assign w_out[9] = w_in[49];
   assign w_out[10] = w_in[41];
   assign w_out[11] = w_in[33];
   assign w_out[12] = w_in[25];
   assign w_out[13] = w_in[17];

   assign w_out[14] = w_in[9];
   assign w_out[15] = w_in[1];
   assign w_out[16] = w_in[58];
   assign w_out[17] = w_in[50];
   assign w_out[18] = w_in[42];
   assign w_out[19] = w_in[34];
   assign w_out[20] = w_in[26];

   assign w_out[21] = w_in[18];
   assign w_out[22] = w_in[10];
   assign w_out[23] = w_in[2];
   assign w_out[24] = w_in[59];
   assign w_out[25] = w_in[51];
   assign w_out[26] = w_in[43];
   assign w_out[27] = w_in[35];

   assign w_out[28] = w_in[62];
   assign w_out[29] = w_in[54];
   assign w_out[30] = w_in[46];
   assign w_out[31] = w_in[38];
   assign w_out[32] = w_in[30];
   assign w_out[33] = w_in[22];
   assign w_out[34] = w_in[14];

   assign w_out[35] = w_in[6];
   assign w_out[36] = w_in[61];
   assign w_out[37] = w_in[53];
   assign w_out[38] = w_in[45];
   assign w_out[39] = w_in[37];
   assign w_out[40] = w_in[29];
   assign w_out[41] = w_in[21];

   assign w_out[42] = w_in[13];
   assign w_out[43] = w_in[5];
   assign w_out[44] = w_in[60];
   assign w_out[45] = w_in[52];
   assign w_out[46] = w_in[44];
   assign w_out[47] = w_in[36];
   assign w_out[48] = w_in[28];

   assign w_out[49] = w_in[20];
   assign w_out[50] = w_in[12];
   assign w_out[51] = w_in[4];
   assign w_out[52] = w_in[27];
   assign w_out[53] = w_in[19];
   assign w_out[54] = w_in[11];
   assign w_out[55] = w_in[3];


endmodule
module pc2(in,out);
   input [55:0] in;
   output [47:0] out;
   genvar 	 i;
   
   wire [55:0] 	 w_in;
   wire [47:0] 	 w_out;
   
   generate
      for(i=0;i<56;i=i+1)
	begin : in_swapper
	   assign w_in[i] = in[55-i];
	end
   endgenerate

   generate
      for(i=0;i<48;i=i+1)
	begin : out_swapper
	   assign out[i] = w_out[47-i];
	end
   endgenerate
   
   assign w_out[0] = w_in[13];
   assign w_out[1] = w_in[16];
   assign w_out[2] = w_in[10];
   assign w_out[3] = w_in[23];
   assign w_out[4] = w_in[0];
   assign w_out[5] = w_in[4];

   assign w_out[6] = w_in[2];
   assign w_out[7] = w_in[27];
   assign w_out[8] = w_in[14];
   assign w_out[9] = w_in[5];
   assign w_out[10] = w_in[20];
   assign w_out[11] = w_in[9];

   assign w_out[12] = w_in[22];
   assign w_out[13] = w_in[18];
   assign w_out[14] = w_in[11];
   assign w_out[15] = w_in[3];
   assign w_out[16] = w_in[25];
   assign w_out[17] = w_in[7];

   assign w_out[18] = w_in[15];
   assign w_out[19] = w_in[6];
   assign w_out[20] = w_in[26];
   assign w_out[21] = w_in[19];
   assign w_out[22] = w_in[12];
   assign w_out[23] = w_in[1];

   assign w_out[24] = w_in[40];
   assign w_out[25] = w_in[51];
   assign w_out[26] = w_in[30];
   assign w_out[27] = w_in[36];
   assign w_out[28] = w_in[46];
   assign w_out[29] = w_in[54];

   assign w_out[30] = w_in[29];
   assign w_out[31] = w_in[39];
   assign w_out[32] = w_in[50];
   assign w_out[33] = w_in[44];
   assign w_out[34] = w_in[32];
   assign w_out[35] = w_in[47];

   assign w_out[36] = w_in[43];
   assign w_out[37] = w_in[48];
   assign w_out[38] = w_in[38];
   assign w_out[39] = w_in[55];
   assign w_out[40] = w_in[33];
   assign w_out[41] = w_in[52];

   assign w_out[42] = w_in[45];
   assign w_out[43] = w_in[41];
   assign w_out[44] = w_in[49];
   assign w_out[45] = w_in[35];
   assign w_out[46] = w_in[28];
   assign w_out[47] = w_in[31];
   
endmodule
module p(in, out);
   input [31:0] in;
   output [31:0] out;
   
   assign out[0] = in[7];
   assign out[1] = in[28];
   assign out[2] = in[21];
   assign out[3] = in[10];
   
   assign out[4] = in[26];
   assign out[5] = in[2];
   assign out[6] = in[19];
   assign out[7] = in[13];
   
   assign out[8] = in[23];
   assign out[9] = in[29];
   assign out[10] = in[5];
   assign out[11] = in[0];
   
   assign out[12] = in[18];
   assign out[13] = in[8];
   assign out[14] = in[24];
   assign out[15] = in[30];
   
   assign out[16] = in[22];
   assign out[17] = in[1];
   assign out[18] = in[14];
   assign out[19] = in[27];
   
   assign out[20] = in[6];
   assign out[21] = in[9];
   assign out[22] = in[17];
   assign out[23] = in[31];
   
   assign out[24] = in[15];
   assign out[25] = in[4];
   assign out[26] = in[20];
   assign out[27] = in[3];
   
   assign out[28] = in[11];
   assign out[29] = in[12];
   assign out[30] = in[25];
   assign out[31] = in[16];

endmodule
//////////////////////////////////////////////////////////////////////
////                                                              ////
////  SBOX 1                                                      ////
////                                                              ////
////  This file is part of the SystemC DES                        ////
////                                                              ////
////  Description:                                                ////
////  Sbox of DES algorithm                                       ////
////                                                              ////
////  Generated automatically using SystemC to Verilog translator ////
////                                                              ////
////  To Do:                                                      ////
////   - done                                                     ////
////                                                              ////
////  Author(s):                                                  ////
////      - Javier Castillo, jcastilo@opencores.org               ////
////                                                              ////
//////////////////////////////////////////////////////////////////////
////                                                              ////
//// Copyright (C) 2000 Authors and OPENCORES.ORG                 ////
////                                                              ////
//// This source file may be used and distributed without         ////
//// restriction provided that this copyright statement is not    ////
//// removed from the file and that any derivative work contains  ////
//// the original copyright notice and the associated disclaimer. ////
////                                                              ////
//// This source file is free software; you can redistribute it   ////
//// and/or modify it under the terms of the GNU Lesser General   ////
//// Public License as published by the Free Software Foundation; ////
//// either version 2.1 of the License, or (at your option) any   ////
//// later version.                                               ////
////                                                              ////
//// This source is distributed in the hope that it will be       ////
//// useful, but WITHOUT ANY WARRANTY; without even the implied   ////
//// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR      ////
//// PURPOSE.  See the GNU Lesser General Public License for more ////
//// details.                                                     ////
////                                                              ////
//// You should have received a copy of the GNU Lesser General    ////
//// Public License along with this source; if not, download it   ////
//// from http://www.opencores.org/lgpl.shtml                     ////
////                                                              ////
//////////////////////////////////////////////////////////////////////
//
// CVS Revision History
//
// $Log: s1.v,v $
// Revision 1.2  2004/09/06 16:41:06  jcastillo
// Indented
//
// Revision 1.1.1.1  2004/07/05 17:31:17  jcastillo
// First import
//


module s1(stage1_input,stage1_output);
input [5:0] stage1_input;
output [3:0] stage1_output;

reg [3:0] stage1_output;


always @(  stage1_input)

begin

	
   case(stage1_input)
	    0: stage1_output = (14); 
        1: stage1_output = (0); 
        2: stage1_output = (4); 
        3: stage1_output = (15); 
        4: stage1_output = (13); 
        5: stage1_output = (7); 
        6: stage1_output = (1); 
        7: stage1_output = (4); 
        8: stage1_output = (2); 
        9: stage1_output = (14); 
        10: stage1_output = (15); 
        11: stage1_output = (2); 
        12: stage1_output = (11); 
        13: stage1_output = (13); 
        14: stage1_output = (8); 
        15: stage1_output = (1); 
        16: stage1_output = (3); 
        17: stage1_output = (10); 
        18: stage1_output = (10); 
        19: stage1_output = (6); 
        20: stage1_output = (6); 
        21: stage1_output = (12); 
        22: stage1_output = (12); 
        23: stage1_output = (11); 
        24: stage1_output = (5); 
        25: stage1_output = (9); 
        26: stage1_output = (9); 
        27: stage1_output = (5); 
        28: stage1_output = (0); 
        29: stage1_output = (3); 
        30: stage1_output = (7); 
        31: stage1_output = (8); 
        32: stage1_output = (4); 
        33: stage1_output = (15); 
        34: stage1_output = (1); 
        35: stage1_output = (12); 
        36: stage1_output = (14); 
        37: stage1_output = (8); 
        38: stage1_output = (8); 
        39: stage1_output = (2); 
        40: stage1_output = (13); 
        41: stage1_output = (4); 
        42: stage1_output = (6); 
        43: stage1_output = (9); 
        44: stage1_output = (2); 
        45: stage1_output = (1); 
        46: stage1_output = (11); 
        47: stage1_output = (7); 
        48: stage1_output = (15); 
        49: stage1_output = (5); 
        50: stage1_output = (12); 
        51: stage1_output = (11); 
        52: stage1_output = (9); 
        53: stage1_output = (3); 
        54: stage1_output = (7); 
        55: stage1_output = (14); 
        56: stage1_output = (3); 
        57: stage1_output = (10); 
        58: stage1_output = (10); 
        59: stage1_output = (0); 
        60: stage1_output = (5); 
        61: stage1_output = (6); 
        62: stage1_output = (0); 
        63: stage1_output = (13); 
    
   endcase

end

endmodule
//////////////////////////////////////////////////////////////////////
////                                                              ////
////  SBOX 2                                                      ////
////                                                              ////
////  This file is part of the SystemC DES                        ////
////                                                              ////
////  Description:                                                ////
////  Sbox of DES algorithm                                       ////
////                                                              ////
////  Generated automatically using SystemC to Verilog translator ////
////                                                              ////
////  To Do:                                                      ////
////   - done                                                     ////
////                                                              ////
////  Author(s):                                                  ////
////      - Javier Castillo, jcastilo@opencores.org               ////
////                                                              ////
//////////////////////////////////////////////////////////////////////
////                                                              ////
//// Copyright (C) 2000 Authors and OPENCORES.ORG                 ////
////                                                              ////
//// This source file may be used and distributed without         ////
//// restriction provided that this copyright statement is not    ////
//// removed from the file and that any derivative work contains  ////
//// the original copyright notice and the associated disclaimer. ////
////                                                              ////
//// This source file is free software; you can redistribute it   ////
//// and/or modify it under the terms of the GNU Lesser General   ////
//// Public License as published by the Free Software Foundation; ////
//// either version 2.1 of the License, or (at your option) any   ////
//// later version.                                               ////
////                                                              ////
//// This source is distributed in the hope that it will be       ////
//// useful, but WITHOUT ANY WARRANTY; without even the implied   ////
//// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR      ////
//// PURPOSE.  See the GNU Lesser General Public License for more ////
//// details.                                                     ////
////                                                              ////
//// You should have received a copy of the GNU Lesser General    ////
//// Public License along with this source; if not, download it   ////
//// from http://www.opencores.org/lgpl.shtml                     ////
////                                                              ////
//////////////////////////////////////////////////////////////////////
//
// CVS Revision History
//
// $Log: s2.v,v $
// Revision 1.2  2004/09/06 16:41:06  jcastillo
// Indented
//
// Revision 1.1.1.1  2004/07/05 17:31:17  jcastillo
// First import
//


module s2(stage1_input,stage1_output);
input [5:0] stage1_input;
output [3:0] stage1_output;

reg [3:0] stage1_output;


always @(  stage1_input)

begin


   case(stage1_input)
        0: stage1_output = (15); 
        1: stage1_output = (3); 
        2: stage1_output = (1); 
        3: stage1_output = (13); 
        4: stage1_output = (8); 
        5: stage1_output = (4); 
        6: stage1_output = (14); 
        7: stage1_output = (7); 
        8: stage1_output = (6); 
        9: stage1_output = (15); 
        10: stage1_output = (11); 
        11: stage1_output = (2); 
        12: stage1_output = (3); 
        13: stage1_output = (8); 
        14: stage1_output = (4); 
        15: stage1_output = (14); 
        16: stage1_output = (9); 
        17: stage1_output = (12); 
        18: stage1_output = (7); 
        19: stage1_output = (0); 
        20: stage1_output = (2); 
        21: stage1_output = (1); 
        22: stage1_output = (13); 
        23: stage1_output = (10); 
        24: stage1_output = (12); 
        25: stage1_output = (6); 
        26: stage1_output = (0); 
        27: stage1_output = (9); 
        28: stage1_output = (5); 
        29: stage1_output = (11); 
        30: stage1_output = (10); 
        31: stage1_output = (5); 
        32: stage1_output = (0); 
        33: stage1_output = (13); 
        34: stage1_output = (14); 
        35: stage1_output = (8); 
        36: stage1_output = (7); 
        37: stage1_output = (10); 
        38: stage1_output = (11); 
        39: stage1_output = (1); 
        40: stage1_output = (10); 
        41: stage1_output = (3); 
        42: stage1_output = (4); 
        43: stage1_output = (15); 
        44: stage1_output = (13); 
        45: stage1_output = (4); 
        46: stage1_output = (1); 
        47: stage1_output = (2); 
        48: stage1_output = (5); 
        49: stage1_output = (11); 
        50: stage1_output = (8); 
        51: stage1_output = (6); 
        52: stage1_output = (12); 
        53: stage1_output = (7); 
        54: stage1_output = (6); 
        55: stage1_output = (12); 
        56: stage1_output = (9); 
        57: stage1_output = (0); 
        58: stage1_output = (3); 
        59: stage1_output = (5); 
        60: stage1_output = (2); 
        61: stage1_output = (14); 
        62: stage1_output = (15); 
        63: stage1_output = (9); 
   
  endcase

end

endmodule
//////////////////////////////////////////////////////////////////////
////                                                              ////
////  SBOX 3                                                      ////
////                                                              ////
////  This file is part of the SystemC DES                        ////
////                                                              ////
////  Description:                                                ////
////  Sbox of DES algorithm                                       ////
////                                                              ////
////  Generated automatically using SystemC to Verilog translator ////
////                                                              ////
////  To Do:                                                      ////
////   - done                                                     ////
////                                                              ////
////  Author(s):                                                  ////
////      - Javier Castillo, jcastilo@opencores.org               ////
////                                                              ////
//////////////////////////////////////////////////////////////////////
////                                                              ////
//// Copyright (C) 2000 Authors and OPENCORES.ORG                 ////
////                                                              ////
//// This source file may be used and distributed without         ////
//// restriction provided that this copyright statement is not    ////
//// removed from the file and that any derivative work contains  ////
//// the original copyright notice and the associated disclaimer. ////
////                                                              ////
//// This source file is free software; you can redistribute it   ////
//// and/or modify it under the terms of the GNU Lesser General   ////
//// Public License as published by the Free Software Foundation; ////
//// either version 2.1 of the License, or (at your option) any   ////
//// later version.                                               ////
////                                                              ////
//// This source is distributed in the hope that it will be       ////
//// useful, but WITHOUT ANY WARRANTY; without even the implied   ////
//// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR      ////
//// PURPOSE.  See the GNU Lesser General Public License for more ////
//// details.                                                     ////
////                                                              ////
//// You should have received a copy of the GNU Lesser General    ////
//// Public License along with this source; if not, download it   ////
//// from http://www.opencores.org/lgpl.shtml                     ////
////                                                              ////
//////////////////////////////////////////////////////////////////////
//
// CVS Revision History
//
// $Log: s3.v,v $
// Revision 1.2  2004/09/06 16:41:06  jcastillo
// Indented
//
// Revision 1.1.1.1  2004/07/05 17:31:17  jcastillo
// First import
//


module s3(stage1_input,stage1_output);
input [5:0] stage1_input;
output [3:0] stage1_output;

reg [3:0] stage1_output;


always @(  stage1_input)

begin

   case(stage1_input)

        0: stage1_output = (10); 
        1: stage1_output = (13); 
        2: stage1_output = (0); 
        3: stage1_output = (7); 
        4: stage1_output = (9); 
        5: stage1_output = (0); 
        6: stage1_output = (14); 
        7: stage1_output = (9); 
        8: stage1_output = (6); 
        9: stage1_output = (3); 
        10: stage1_output = (3); 
        11: stage1_output = (4); 
        12: stage1_output = (15); 
        13: stage1_output = (6); 
        14: stage1_output = (5); 
        15: stage1_output = (10); 
        16: stage1_output = (1); 
        17: stage1_output = (2); 
        18: stage1_output = (13); 
        19: stage1_output = (8); 
        20: stage1_output = (12); 
        21: stage1_output = (5); 
        22: stage1_output = (7); 
        23: stage1_output = (14); 
        24: stage1_output = (11); 
        25: stage1_output = (12); 
        26: stage1_output = (4); 
        27: stage1_output = (11); 
        28: stage1_output = (2); 
        29: stage1_output = (15); 
        30: stage1_output = (8); 
        31: stage1_output = (1); 
        32: stage1_output = (13); 
        33: stage1_output = (1); 
        34: stage1_output = (6); 
        35: stage1_output = (10); 
        36: stage1_output = (4); 
        37: stage1_output = (13); 
        38: stage1_output = (9); 
        39: stage1_output = (0); 
        40: stage1_output = (8); 
        41: stage1_output = (6); 
        42: stage1_output = (15); 
        43: stage1_output = (9); 
        44: stage1_output = (3); 
        45: stage1_output = (8); 
        46: stage1_output = (0); 
        47: stage1_output = (7); 
        48: stage1_output = (11); 
        49: stage1_output = (4); 
        50: stage1_output = (1); 
        51: stage1_output = (15); 
        52: stage1_output = (2); 
        53: stage1_output = (14); 
        54: stage1_output = (12); 
        55: stage1_output = (3); 
        56: stage1_output = (5); 
        57: stage1_output = (11); 
        58: stage1_output = (10); 
        59: stage1_output = (5); 
        60: stage1_output = (14); 
        61: stage1_output = (2); 
        62: stage1_output = (7); 
        63: stage1_output = (12); 
  
   endcase

end

endmodule
//////////////////////////////////////////////////////////////////////
////                                                              ////
////  SBOX 4                                                      ////
////                                                              ////
////  This file is part of the SystemC DES                        ////
////                                                              ////
////  Description:                                                ////
////  Sbox of DES algorithm                                       ////
////                                                              ////
////  Generated automatically using SystemC to Verilog translator ////
////                                                              ////
////  To Do:                                                      ////
////   - done                                                     ////
////                                                              ////
////  Author(s):                                                  ////
////      - Javier Castillo, jcastilo@opencores.org               ////
////                                                              ////
//////////////////////////////////////////////////////////////////////
////                                                              ////
//// Copyright (C) 2000 Authors and OPENCORES.ORG                 ////
////                                                              ////
//// This source file may be used and distributed without         ////
//// restriction provided that this copyright statement is not    ////
//// removed from the file and that any derivative work contains  ////
//// the original copyright notice and the associated disclaimer. ////
////                                                              ////
//// This source file is free software; you can redistribute it   ////
//// and/or modify it under the terms of the GNU Lesser General   ////
//// Public License as published by the Free Software Foundation; ////
//// either version 2.1 of the License, or (at your option) any   ////
//// later version.                                               ////
////                                                              ////
//// This source is distributed in the hope that it will be       ////
//// useful, but WITHOUT ANY WARRANTY; without even the implied   ////
//// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR      ////
//// PURPOSE.  See the GNU Lesser General Public License for more ////
//// details.                                                     ////
////                                                              ////
//// You should have received a copy of the GNU Lesser General    ////
//// Public License along with this source; if not, download it   ////
//// from http://www.opencores.org/lgpl.shtml                     ////
////                                                              ////
//////////////////////////////////////////////////////////////////////
//
// CVS Revision History
//
// $Log: s4.v,v $
// Revision 1.2  2004/09/06 16:41:06  jcastillo
// Indented
//
// Revision 1.1.1.1  2004/07/05 17:31:17  jcastillo
// First import
//


module s4(stage1_input,stage1_output);
input [5:0] stage1_input;
output [3:0] stage1_output;

reg [3:0] stage1_output;


always @(  stage1_input)

begin

   case(stage1_input)

        0: stage1_output = (7); 
        1: stage1_output = (13); 
        2: stage1_output = (13); 
        3: stage1_output = (8); 
        4: stage1_output = (14); 
        5: stage1_output = (11); 
        6: stage1_output = (3); 
        7: stage1_output = (5); 
        8: stage1_output = (0); 
        9: stage1_output = (6); 
        10: stage1_output = (6); 
        11: stage1_output = (15); 
        12: stage1_output = (9); 
        13: stage1_output = (0); 
        14: stage1_output = (10); 
        15: stage1_output = (3); 
        16: stage1_output = (1); 
        17: stage1_output = (4); 
        18: stage1_output = (2); 
        19: stage1_output = (7); 
        20: stage1_output = (8); 
        21: stage1_output = (2); 
        22: stage1_output = (5); 
        23: stage1_output = (12); 
        24: stage1_output = (11); 
        25: stage1_output = (1); 
        26: stage1_output = (12); 
        27: stage1_output = (10); 
        28: stage1_output = (4); 
        29: stage1_output = (14); 
        30: stage1_output = (15); 
        31: stage1_output = (9); 
        32: stage1_output = (10); 
        33: stage1_output = (3); 
        34: stage1_output = (6); 
        35: stage1_output = (15); 
        36: stage1_output = (9); 
        37: stage1_output = (0); 
        38: stage1_output = (0); 
        39: stage1_output = (6); 
        40: stage1_output = (12); 
        41: stage1_output = (10); 
        42: stage1_output = (11); 
        43: stage1_output = (1); 
        44: stage1_output = (7); 
        45: stage1_output = (13); 
        46: stage1_output = (13); 
        47: stage1_output = (8); 
        48: stage1_output = (15); 
        49: stage1_output = (9); 
        50: stage1_output = (1); 
        51: stage1_output = (4); 
        52: stage1_output = (3); 
        53: stage1_output = (5); 
        54: stage1_output = (14); 
        55: stage1_output = (11); 
        56: stage1_output = (5); 
        57: stage1_output = (12); 
        58: stage1_output = (2); 
        59: stage1_output = (7); 
        60: stage1_output = (8); 
        61: stage1_output = (2); 
        62: stage1_output = (4); 
        63: stage1_output = (14); 

   endcase

end

endmodule
//////////////////////////////////////////////////////////////////////
////                                                              ////
////  SBOX 5                                                      ////
////                                                              ////
////  This file is part of the SystemC DES                        ////
////                                                              ////
////  Description:                                                ////
////  Sbox of DES algorithm                                       ////
////                                                              ////
////  Generated automatically using SystemC to Verilog translator ////
////                                                              ////
////  To Do:                                                      ////
////   - done                                                     ////
////                                                              ////
////  Author(s):                                                  ////
////      - Javier Castillo, jcastilo@opencores.org               ////
////                                                              ////
//////////////////////////////////////////////////////////////////////
////                                                              ////
//// Copyright (C) 2000 Authors and OPENCORES.ORG                 ////
////                                                              ////
//// This source file may be used and distributed without         ////
//// restriction provided that this copyright statement is not    ////
//// removed from the file and that any derivative work contains  ////
//// the original copyright notice and the associated disclaimer. ////
////                                                              ////
//// This source file is free software; you can redistribute it   ////
//// and/or modify it under the terms of the GNU Lesser General   ////
//// Public License as published by the Free Software Foundation; ////
//// either version 2.1 of the License, or (at your option) any   ////
//// later version.                                               ////
////                                                              ////
//// This source is distributed in the hope that it will be       ////
//// useful, but WITHOUT ANY WARRANTY; without even the implied   ////
//// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR      ////
//// PURPOSE.  See the GNU Lesser General Public License for more ////
//// details.                                                     ////
////                                                              ////
//// You should have received a copy of the GNU Lesser General    ////
//// Public License along with this source; if not, download it   ////
//// from http://www.opencores.org/lgpl.shtml                     ////
////                                                              ////
//////////////////////////////////////////////////////////////////////
//
// CVS Revision History
//
// $Log: s5.v,v $
// Revision 1.2  2004/09/06 16:41:06  jcastillo
// Indented
//
// Revision 1.1.1.1  2004/07/05 17:31:17  jcastillo
// First import
//


module s5(stage1_input,stage1_output);
input [5:0] stage1_input;
output [3:0] stage1_output;

reg [3:0] stage1_output;


always @(  stage1_input)

begin

   case(stage1_input)

        0: stage1_output = (2); 
        1: stage1_output = (14); 
        2: stage1_output = (12); 
        3: stage1_output = (11); 
        4: stage1_output = (4); 
        5: stage1_output = (2); 
        6: stage1_output = (1); 
        7: stage1_output = (12); 
        8: stage1_output = (7); 
        9: stage1_output = (4); 
        10: stage1_output = (10); 
        11: stage1_output = (7); 
        12: stage1_output = (11); 
        13: stage1_output = (13); 
        14: stage1_output = (6); 
        15: stage1_output = (1); 
        16: stage1_output = (8); 
        17: stage1_output = (5); 
        18: stage1_output = (5); 
        19: stage1_output = (0); 
        20: stage1_output = (3); 
        21: stage1_output = (15); 
        22: stage1_output = (15); 
        23: stage1_output = (10); 
        24: stage1_output = (13); 
        25: stage1_output = (3); 
        26: stage1_output = (0); 
        27: stage1_output = (9); 
        28: stage1_output = (14); 
        29: stage1_output = (8); 
        30: stage1_output = (9); 
        31: stage1_output = (6); 
        32: stage1_output = (4); 
        33: stage1_output = (11); 
        34: stage1_output = (2); 
        35: stage1_output = (8); 
        36: stage1_output = (1); 
        37: stage1_output = (12); 
        38: stage1_output = (11); 
        39: stage1_output = (7); 
        40: stage1_output = (10); 
        41: stage1_output = (1); 
        42: stage1_output = (13); 
        43: stage1_output = (14); 
        44: stage1_output = (7); 
        45: stage1_output = (2); 
        46: stage1_output = (8); 
        47: stage1_output = (13); 
        48: stage1_output = (15); 
        49: stage1_output = (6); 
        50: stage1_output = (9); 
        51: stage1_output = (15); 
        52: stage1_output = (12); 
        53: stage1_output = (0); 
        54: stage1_output = (5); 
        55: stage1_output = (9); 
        56: stage1_output = (6); 
        57: stage1_output = (10); 
        58: stage1_output = (3); 
        59: stage1_output = (4); 
        60: stage1_output = (0); 
        61: stage1_output = (5); 
        62: stage1_output = (14); 
        63: stage1_output = (3); 

   endcase


end

endmodule
//////////////////////////////////////////////////////////////////////
////                                                              ////
////  SBOX 6                                                      ////
////                                                              ////
////  This file is part of the SystemC DES                        ////
////                                                              ////
////  Description:                                                ////
////  Sbox of DES algorithm                                       ////
////                                                              ////
////  Generated automatically using SystemC to Verilog translator ////
////                                                              ////
////  To Do:                                                      ////
////   - done                                                     ////
////                                                              ////
////  Author(s):                                                  ////
////      - Javier Castillo, jcastilo@opencores.org               ////
////                                                              ////
//////////////////////////////////////////////////////////////////////
////                                                              ////
//// Copyright (C) 2000 Authors and OPENCORES.ORG                 ////
////                                                              ////
//// This source file may be used and distributed without         ////
//// restriction provided that this copyright statement is not    ////
//// removed from the file and that any derivative work contains  ////
//// the original copyright notice and the associated disclaimer. ////
////                                                              ////
//// This source file is free software; you can redistribute it   ////
//// and/or modify it under the terms of the GNU Lesser General   ////
//// Public License as published by the Free Software Foundation; ////
//// either version 2.1 of the License, or (at your option) any   ////
//// later version.                                               ////
////                                                              ////
//// This source is distributed in the hope that it will be       ////
//// useful, but WITHOUT ANY WARRANTY; without even the implied   ////
//// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR      ////
//// PURPOSE.  See the GNU Lesser General Public License for more ////
//// details.                                                     ////
////                                                              ////
//// You should have received a copy of the GNU Lesser General    ////
//// Public License along with this source; if not, download it   ////
//// from http://www.opencores.org/lgpl.shtml                     ////
////                                                              ////
//////////////////////////////////////////////////////////////////////
//
// CVS Revision History
//
// $Log: s6.v,v $
// Revision 1.2  2004/09/06 16:41:06  jcastillo
// Indented
//
// Revision 1.1.1.1  2004/07/05 17:31:17  jcastillo
// First import
//


module s6(stage1_input,stage1_output);
input [5:0] stage1_input;
output [3:0] stage1_output;

reg [3:0] stage1_output;


always @(  stage1_input)

begin

   case(stage1_input)

        0: stage1_output = (12); 
        1: stage1_output = (10); 
        2: stage1_output = (1); 
        3: stage1_output = (15); 
        4: stage1_output = (10); 
        5: stage1_output = (4); 
        6: stage1_output = (15); 
        7: stage1_output = (2); 
        8: stage1_output = (9); 
        9: stage1_output = (7); 
        10: stage1_output = (2); 
        11: stage1_output = (12); 
        12: stage1_output = (6); 
        13: stage1_output = (9); 
        14: stage1_output = (8); 
        15: stage1_output = (5); 
        16: stage1_output = (0); 
        17: stage1_output = (6); 
        18: stage1_output = (13); 
        19: stage1_output = (1); 
        20: stage1_output = (3); 
        21: stage1_output = (13); 
        22: stage1_output = (4); 
        23: stage1_output = (14); 
        24: stage1_output = (14); 
        25: stage1_output = (0); 
        26: stage1_output = (7); 
        27: stage1_output = (11); 
        28: stage1_output = (5); 
        29: stage1_output = (3); 
        30: stage1_output = (11); 
        31: stage1_output = (8); 
        32: stage1_output = (9); 
        33: stage1_output = (4); 
        34: stage1_output = (14); 
        35: stage1_output = (3); 
        36: stage1_output = (15); 
        37: stage1_output = (2); 
        38: stage1_output = (5); 
        39: stage1_output = (12); 
        40: stage1_output = (2); 
        41: stage1_output = (9); 
        42: stage1_output = (8); 
        43: stage1_output = (5); 
        44: stage1_output = (12); 
        45: stage1_output = (15); 
        46: stage1_output = (3); 
        47: stage1_output = (10); 
        48: stage1_output = (7); 
        49: stage1_output = (11); 
        50: stage1_output = (0); 
        51: stage1_output = (14); 
        52: stage1_output = (4); 
        53: stage1_output = (1); 
        54: stage1_output = (10); 
        55: stage1_output = (7); 
        56: stage1_output = (1); 
        57: stage1_output = (6); 
        58: stage1_output = (13); 
        59: stage1_output = (0); 
        60: stage1_output = (11); 
        61: stage1_output = (8); 
        62: stage1_output = (6); 
        63: stage1_output = (13); 

   endcase
	

end

endmodule
//////////////////////////////////////////////////////////////////////
////                                                              ////
////  SBOX 7                                                      ////
////                                                              ////
////  This file is part of the SystemC DES                        ////
////                                                              ////
////  Description:                                                ////
////  Sbox of DES algorithm                                       ////
////                                                              ////
////  Generated automatically using SystemC to Verilog translator ////
////                                                              ////
////  To Do:                                                      ////
////   - done                                                     ////
////                                                              ////
////  Author(s):                                                  ////
////      - Javier Castillo, jcastilo@opencores.org               ////
////                                                              ////
//////////////////////////////////////////////////////////////////////
////                                                              ////
//// Copyright (C) 2000 Authors and OPENCORES.ORG                 ////
////                                                              ////
//// This source file may be used and distributed without         ////
//// restriction provided that this copyright statement is not    ////
//// removed from the file and that any derivative work contains  ////
//// the original copyright notice and the associated disclaimer. ////
////                                                              ////
//// This source file is free software; you can redistribute it   ////
//// and/or modify it under the terms of the GNU Lesser General   ////
//// Public License as published by the Free Software Foundation; ////
//// either version 2.1 of the License, or (at your option) any   ////
//// later version.                                               ////
////                                                              ////
//// This source is distributed in the hope that it will be       ////
//// useful, but WITHOUT ANY WARRANTY; without even the implied   ////
//// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR      ////
//// PURPOSE.  See the GNU Lesser General Public License for more ////
//// details.                                                     ////
////                                                              ////
//// You should have received a copy of the GNU Lesser General    ////
//// Public License along with this source; if not, download it   ////
//// from http://www.opencores.org/lgpl.shtml                     ////
////                                                              ////
//////////////////////////////////////////////////////////////////////
//
// CVS Revision History
//
// $Log: s7.v,v $
// Revision 1.2  2004/09/06 16:41:06  jcastillo
// Indented
//
// Revision 1.1.1.1  2004/07/05 17:31:17  jcastillo
// First import
//

module s7(stage1_input,stage1_output);
input [5:0] stage1_input;
output [3:0] stage1_output;

reg [3:0] stage1_output;


always @(  stage1_input)

begin

   case(stage1_input)

        0: stage1_output = (4); 
        1: stage1_output = (13); 
        2: stage1_output = (11); 
        3: stage1_output = (0); 
        4: stage1_output = (2); 
        5: stage1_output = (11); 
        6: stage1_output = (14); 
        7: stage1_output = (7); 
        8: stage1_output = (15); 
        9: stage1_output = (4); 
        10: stage1_output = (0); 
        11: stage1_output = (9); 
        12: stage1_output = (8); 
        13: stage1_output = (1); 
        14: stage1_output = (13); 
        15: stage1_output = (10); 
        16: stage1_output = (3); 
        17: stage1_output = (14); 
        18: stage1_output = (12); 
        19: stage1_output = (3); 
        20: stage1_output = (9); 
        21: stage1_output = (5); 
        22: stage1_output = (7); 
        23: stage1_output = (12); 
        24: stage1_output = (5); 
        25: stage1_output = (2); 
        26: stage1_output = (10); 
        27: stage1_output = (15); 
        28: stage1_output = (6); 
        29: stage1_output = (8); 
        30: stage1_output = (1); 
        31: stage1_output = (6); 
        32: stage1_output = (1); 
        33: stage1_output = (6); 
        34: stage1_output = (4); 
        35: stage1_output = (11); 
        36: stage1_output = (11); 
        37: stage1_output = (13); 
        38: stage1_output = (13); 
        39: stage1_output = (8); 
        40: stage1_output = (12); 
        41: stage1_output = (1); 
        42: stage1_output = (3); 
        43: stage1_output = (4); 
        44: stage1_output = (7); 
        45: stage1_output = (10); 
        46: stage1_output = (14); 
        47: stage1_output = (7); 
        48: stage1_output = (10); 
        49: stage1_output = (9); 
        50: stage1_output = (15); 
        51: stage1_output = (5); 
        52: stage1_output = (6); 
        53: stage1_output = (0); 
        54: stage1_output = (8); 
        55: stage1_output = (15); 
        56: stage1_output = (0); 
        57: stage1_output = (14); 
        58: stage1_output = (5); 
        59: stage1_output = (2); 
        60: stage1_output = (9); 
        61: stage1_output = (3); 
        62: stage1_output = (2); 
        63: stage1_output = (12); 

   endcase


end

endmodule
//////////////////////////////////////////////////////////////////////
////                                                              ////
////  SBOX 8                                                      ////
////                                                              ////
////  This file is part of the SystemC DES                        ////
////                                                              ////
////  Description:                                                ////
////  Sbox of DES algorithm                                       ////
////                                                              ////
////  Generated automatically using SystemC to Verilog translator ////
////                                                              ////
////  To Do:                                                      ////
////   - done                                                     ////
////                                                              ////
////  Author(s):                                                  ////
////      - Javier Castillo, jcastilo@opencores.org               ////
////                                                              ////
//////////////////////////////////////////////////////////////////////
////                                                              ////
//// Copyright (C) 2000 Authors and OPENCORES.ORG                 ////
////                                                              ////
//// This source file may be used and distributed without         ////
//// restriction provided that this copyright statement is not    ////
//// removed from the file and that any derivative work contains  ////
//// the original copyright notice and the associated disclaimer. ////
////                                                              ////
//// This source file is free software; you can redistribute it   ////
//// and/or modify it under the terms of the GNU Lesser General   ////
//// Public License as published by the Free Software Foundation; ////
//// either version 2.1 of the License, or (at your option) any   ////
//// later version.                                               ////
////                                                              ////
//// This source is distributed in the hope that it will be       ////
//// useful, but WITHOUT ANY WARRANTY; without even the implied   ////
//// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR      ////
//// PURPOSE.  See the GNU Lesser General Public License for more ////
//// details.                                                     ////
////                                                              ////
//// You should have received a copy of the GNU Lesser General    ////
//// Public License along with this source; if not, download it   ////
//// from http://www.opencores.org/lgpl.shtml                     ////
////                                                              ////
//////////////////////////////////////////////////////////////////////
//
// CVS Revision History
//
// $Log: s8.v,v $
// Revision 1.2  2004/09/06 16:41:06  jcastillo
// Indented
//
// Revision 1.1.1.1  2004/07/05 17:31:17  jcastillo
// First import
//

module s8(stage1_input,stage1_output);
input [5:0] stage1_input;
output [3:0] stage1_output;

reg [3:0] stage1_output;


always @(stage1_input)

begin

   case(stage1_input)

        0: stage1_output = (13); 
        1: stage1_output = (1); 
        2: stage1_output = (2); 
        3: stage1_output = (15); 
        4: stage1_output = (8); 
        5: stage1_output = (13); 
        6: stage1_output = (4); 
        7: stage1_output = (8); 
        8: stage1_output = (6); 
        9: stage1_output = (10); 
        10: stage1_output = (15); 
        11: stage1_output = (3); 
        12: stage1_output = (11); 
        13: stage1_output = (7); 
        14: stage1_output = (1); 
        15: stage1_output = (4); 
        16: stage1_output = (10); 
        17: stage1_output = (12); 
        18: stage1_output = (9); 
        19: stage1_output = (5); 
        20: stage1_output = (3); 
        21: stage1_output = (6); 
        22: stage1_output = (14); 
        23: stage1_output = (11); 
        24: stage1_output = (5); 
        25: stage1_output = (0); 
        26: stage1_output = (0); 
        27: stage1_output = (14); 
        28: stage1_output = (12); 
        29: stage1_output = (9); 
        30: stage1_output = (7); 
        31: stage1_output = (2); 
        32: stage1_output = (7); 
        33: stage1_output = (2); 
        34: stage1_output = (11); 
        35: stage1_output = (1); 
        36: stage1_output = (4); 
        37: stage1_output = (14); 
        38: stage1_output = (1); 
        39: stage1_output = (7); 
        40: stage1_output = (9); 
        41: stage1_output = (4); 
        42: stage1_output = (12); 
        43: stage1_output = (10); 
        44: stage1_output = (14); 
        45: stage1_output = (8); 
        46: stage1_output = (2); 
        47: stage1_output = (13); 
        48: stage1_output = (0); 
        49: stage1_output = (15); 
        50: stage1_output = (6); 
        51: stage1_output = (12); 
        52: stage1_output = (10); 
        53: stage1_output = (9); 
        54: stage1_output = (13); 
        55: stage1_output = (0); 
        56: stage1_output = (15); 
        57: stage1_output = (3); 
        58: stage1_output = (3); 
        59: stage1_output = (5); 
        60: stage1_output = (5); 
        61: stage1_output = (6); 
        62: stage1_output = (8); 
        63: stage1_output = (11); 

   endcase


end

endmodule

module top(/*AUTOARG*/
   // Outputs
   found, key,
   // Inputs
   clk, rst, startkey, plaintext, ciphertext
   );
   input clk;
   input rst;
   input [63:0] startkey;
   input [63:0] plaintext;
   input [63:0] ciphertext;
   output 	found;
   output [63:0] key;

   parameter NUM_PEs = 32;

   wire [55:0] 	 w_key [NUM_PEs-1:0];
   wire 	 w_found [NUM_PEs-1:0];


   wire [55:0] 	 w_key56;
   
   dropkeyparity d (
		    .key56_out		(w_key56),
		    .key64_in		(startkey)
		    );

   assign found = w_found[0];   
   addkeyparity #(.XOR(1)) a (
			      .key64_out		(key),
			      .key56_in		(w_key[0])
			      );
   
   
   genvar 	 i;
   generate
      for(i=0;i<NUM_PEs;i=i+1)
	begin: des_cracker
	   cracker #(.ID(i), .NUM_PEs(NUM_PEs)) c
	   (
	    // Outputs
	    .key_out		(w_key[i]),
	    .found_out		(w_found[i]),
	    // Inputs
	    .clk		(clk),
	    .rst		(rst),
	    .startkey           (w_key56),
	    .plaintext		(plaintext),
	    .ciphertext		(ciphertext),
	    .found_in		(i==0 ? w_found[NUM_PEs-1] : w_found[i-1]),
	    .key_in		(i==0 ? w_key[NUM_PEs-1] : w_key[i-1])
	    );
	end
   endgenerate
   

endmodule
