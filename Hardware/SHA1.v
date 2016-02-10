`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date:    20:31:52 02/09/2016 
// Design Name: 
// Module Name:    SHA1 
// Project Name: 
// Target Devices: 
// Tool versions: 
// Description: 
//
// Dependencies: 
//
// Revision: 
// Revision 0.01 - File Created
// Additional Comments: 
//
//////////////////////////////////////////////////////////////////////////////////
module SHA1();



endmodule

module and_gate32(a,b,y);
	input [31:0] a, b;
	output [31:0] y;
	
	assign y = a & b;
	
endmodule

module not_gate32(a,y);
	input [31:0] a;
	output [31:0] y;
	
	assign y = ~a;
	
endmodule

module xor_gate32(a, b, y);
	input  [31:0] a, b;
	output [31:0] y;
	
	assign y = a ^ b;

endmodule

module or_gate32(a, b, y);
	input  [31:0] a, b;
	output [31:0] y;
	
	assign y = a | b;
	
endmodule

module add_32(a, b, y);
	input  [31:0] a, b;
	output [31:0] y;
	
	wire cout0, cout1, cout2, cout3, cout4, cout5, cout6,
	cout7, cout8, cout9, cout10, cout11, cout12, cout13,
	cout14, cout15, cout16, cout17, cout18, cout19, cout20,
	cout21, cout22, cout23, cout24, cout25, cout26, cout27,
	cout28, cout29, cout30, cout31;
	
	full_adder add0(a[0], b[0], 0, cout0, y[0]);
	full_adder add1(a[1], b[1], cout0, cout1, y[1]);
	full_adder add2(a[2], b[2], cout1, cout2, y[2]);
	full_adder add3(a[3], b[3], cout2, cout3, y[3]);
	full_adder add4(a[4], b[4], cout3, cout4, y[4]);
	full_adder add5(a[5], b[5], cout4, cout5, y[5]);
	full_adder add6(a[6], b[6], cout5, cout6, y[6]);
	full_adder add7(a[7], b[7], cout6, cout7, y[7]);
	full_adder add8(a[8], b[8], cout7, cout8, y[8]);
	full_adder add9(a[9], b[9], cout8, cout9, y[9]);
	full_adder add10(a[10], b[10], cout9, cout10, y[10]);
	full_adder add11(a[11], b[11], cout10, cout11, y[11]);
	full_adder add12(a[12], b[12], cout11, cout12, y[12]);
	full_adder add13(a[13], b[13], cout12, cout13, y[13]);
	full_adder add14(a[14], b[14], cout13, cout14, y[14]);
	full_adder add15(a[15], b[15], cout14, cout15, y[15]);
	full_adder add16(a[16], b[16], cout15, cout16, y[16]);
	full_adder add17(a[17], b[17], cout16, cout17, y[17]);
	full_adder add18(a[18], b[18], cout17, cout18, y[18]);
	full_adder add19(a[19], b[19], cout18, cout19, y[19]);
	full_adder add20(a[20], b[20], cout19, cout20, y[20]);
	full_adder add21(a[21], b[21], cout20, cout21, y[21]);
	full_adder add22(a[22], b[22], cout21, cout22, y[22]);
	full_adder add23(a[23], b[23], cout22, cout23, y[23]);
	full_adder add24(a[24], b[24], cout23, cout24, y[24]);
	full_adder add25(a[25], b[25], cout24, cout25, y[25]);
	full_adder add26(a[26], b[26], cout25, cout26, y[26]);
	full_adder add27(a[27], b[27], cout26, cout27, y[27]);
	full_adder add28(a[28], b[28], cout27, cout28, y[28]);
	full_adder add29(a[29], b[29], cout28, cout29, y[29]);
	full_adder add30(a[30], b[30], cout29, cout30, y[30]);
	full_adder add31(a[31], b[31], cout30, cout31, y[31]);
	
endmodule


module full_adder(a, b, cin, cout, s);
		input a, b, cin;
		output cout, s;
		
		wire w1, w2, w3;
		
		and(w1, a, b);
		and(w2, a, cin);
		and(w3, b, cin);
		or(cout, w1, w2, w3);
		
		xor(s, a, b, cin);
	
endmodule 

module left_rotate1(a,y);
	input [31:0] a;
	output [31:0] y;
	
	assign y[0] = a[31];
	assign y[1] = a[0];
	assign y[2] = a[1];
	assign y[3] = a[2];
	assign y[4] = a[3];
	assign y[5] = a[4];
	assign y[6] = a[5];
	assign y[7] = a[6];
	assign y[8] = a[7];
	assign y[9] = a[8];
	assign y[10] = a[9];
	assign y[11] = a[10];
	assign y[12] = a[11];
	assign y[13] = a[12];
	assign y[14] = a[13];
	assign y[15] = a[14];
	assign y[16] = a[15];
	assign y[17] = a[16];
	assign y[18] = a[17];
	assign y[19] = a[18];
	assign y[20] = a[19];
	assign y[21] = a[20];
	assign y[22] = a[21];
	assign y[23] = a[22];
	assign y[24] = a[23];
	assign y[25] = a[24];
	assign y[26] = a[25];
	assign y[27] = a[26];
	assign y[28] = a[27];
	assign y[29] = a[28];
	assign y[30] = a[29];
	assign y[31] = a[30];
	
endmodule

module left_rotate5(a,y);
	input [31:0] a;
	output [31:0] y;
	
	assign y[0] = a[27];
	assign y[1] = a[28];
	assign y[2] = a[29];
	assign y[3] = a[30];
	assign y[4] = a[31];
	assign y[5] = a[0];
	assign y[6] = a[1];
	assign y[7] = a[2];
	assign y[8] = a[3];
	assign y[9] = a[4];
	assign y[10] = a[5];
	assign y[11] = a[6];
	assign y[12] = a[7];
	assign y[13] = a[8];
	assign y[14] = a[9];
	assign y[15] = a[10];
	assign y[16] = a[11];
	assign y[17] = a[12];
	assign y[18] = a[13];
	assign y[19] = a[14];
	assign y[20] = a[15];
	assign y[21] = a[16];
	assign y[22] = a[17];
	assign y[23] = a[18];
	assign y[24] = a[19];
	assign y[25] = a[20];
	assign y[26] = a[21];
	assign y[27] = a[22];
	assign y[28] = a[23];
	assign y[29] = a[24];
	assign y[30] = a[25];
	assign y[31] = a[26];
	
endmodule

module left_rotate30(a,y);
	input [31:0] a;
	output [31:0] y;
	
	assign y[0] = a[2];
	assign y[1] = a[3];
	assign y[2] = a[4];
	assign y[3] = a[5];
	assign y[4] = a[6];
	assign y[5] = a[7];
	assign y[6] = a[8];
	assign y[7] = a[9];
	assign y[8] = a[10];
	assign y[9] = a[11];
	assign y[10] = a[12];
	assign y[11] = a[13];
	assign y[12] = a[14];
	assign y[13] = a[15];
	assign y[14] = a[16];
	assign y[15] = a[17];
	assign y[16] = a[18];
	assign y[17] = a[19];
	assign y[18] = a[20];
	assign y[19] = a[21];
	assign y[20] = a[22];
	assign y[21] = a[23];
	assign y[22] = a[24];
	assign y[23] = a[25];
	assign y[24] = a[26];
	assign y[25] = a[27];
	assign y[26] = a[28];
	assign y[27] = a[29];
	assign y[28] = a[30];
	assign y[29] = a[31];
	assign y[30] = a[0];
	assign y[31] = a[1];
	
endmodule

module w_expand(w1, w2, w3, w4, wout);
	input [31:0] w1, w2, w3, w4;
	output [31:0] wout;
	
	wire [31:0] wire1, wire2, wire3;
	
	xor_gate32 xor1(w1, w2, wire1);
	xor_gate32 xor2(w3, w4, wire2);
	xor_gate32 xor3(wire1,wire2,wire3);
	
	left_rotate1 rotate(wire3,wout);
	
endmodule

module f0(b, c, d, y);
	input [31:0] b, c, d;
	output [31:0] y;
	
	wire [31:0] wire1, wire2, wire3;
	
	and_gate32 and1(b,c,wire1);
	not_gate32 NOT(b,wire2);
	and_gate32 and2(wire2,d,wire3);
	or_gate32 or1(wire3,wire1,y);
	
endmodule

module f1(b, c, d, y);
	input [31:0] b, c, d;
	output [31:0] y;
	
	wire [31:0] wire1;
	
	xor_gate32 xor1(b,c,wire1);
	xor_gate32 xor2(wire1,d,y);
	
endmodule

module f2(b, c, d, y);
	input [31:0] b, c, d;
	output [31:0] y;
	
	wire [31:0] wire1, wire2, wire3, wire4;
	
	and_gate32 and1(b,c,wire1);
	and_gate32 and2(b,d,wire2);
	and_gate32 and3(c,d,wire3);
	or_gate32 or1(wire1,wire2,wire4);
	or_gate32 or2(wire3,wire4,y);
	
endmodule

module f3(b, c, d, y);
	input [31:0] b, c, d;
	output [31:0] y;
	
	wire [31:0] wire1;
	
	xor_gate32 xor1(b,c,wire1);
	xor_gate32 xor2(wire1,d,y);
	
endmodule