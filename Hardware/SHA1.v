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
module SHA1(clk, hash);
	input clk;
	output [159:0] hash;
	
	//Test password: aabb
	parameter [31:0] M0  = 32'h61616262;
	parameter [31:0] M1  = 32'h80000000;
	parameter [31:0] M2  = 32'h00000000;
	parameter [31:0] M3  = 32'h00000000;
	parameter [31:0] M4  = 32'h00000000;
	parameter [31:0] M5  = 32'h00000000;
	parameter [31:0] M6  = 32'h00000000;
	parameter [31:0] M7  = 32'h00000000;
	parameter [31:0] M8  = 32'h00000000;
	parameter [31:0] M9 = 32'h00000000;
	parameter [31:0] M10 = 32'h00000000;
	parameter [31:0] M11 = 32'h00000000;
	parameter [31:0] M12 = 32'h00000000;
	parameter [31:0] M13 = 32'h00000000;
	parameter [31:0] M14 = 32'h00000000;
	parameter [31:0] M15 = 32'h00000020;
	
	//Initial Buffer Values
	parameter [31:0] h0 = 32'h67452301;
	parameter [31:0] h1 = 32'hEFCDAB89;
	parameter [31:0] h2 = 32'h98BADCFE;
	parameter [31:0] h3 = 32'h10325476;
	parameter [31:0] h4 = 32'hC3D2E1F0;
	
	//K Values
	parameter [31:0] k0 = 32'h5A827999;
	parameter [31:0] k1 = 32'h6ED9EBA1;
	parameter [31:0] k2 = 32'h8F1BBCDC;
	parameter [31:0] k3 = 32'hCA62C1D6;
	
	//w[0] through w[15]
	wire [31:0] w0,w1,w2,w3;
	wire [31:0] w4,w5,w6,w7;
	wire [31:0] w8,w9,w10,w11;
	wire [31:0] w12,w13,w14,w15;
	
	//w[16] through w[79]
	wire [31:0] w16,w17,w18,w19;
	wire [31:0] w20,w21,w22,w23;
	wire [31:0] w24,w25,w26,w27;
	wire [31:0] w28,w29,w30,w31;
	wire [31:0] w32,w33,w34,w35;
	wire [31:0] w36,w37,w38,w39;
	wire [31:0] w40,w41,w42,w43;
	wire [31:0] w44,w45,w46,w47;
	wire [31:0] w48,w49,w50,w51;
	wire [31:0] w52,w53,w54,w55;
	wire [31:0] w56,w57,w58,w59;
	wire [31:0] w60,w61,w62,w63;
	wire [31:0] w64,w65,w66,w67;
	wire [31:0] w68,w69,w70,w71;
	wire [31:0] w72,w73,w74,w75;
	wire [31:0] w76,w77,w78,w79;
	
	wire [31:0] a1,b1,c1,d1,e1;
	wire [31:0] a2,b2,c2,d2,e2;
	wire [31:0] a3,b3,c3,d3,e3;
	wire [31:0] a4,b4,c4,d4,e4;
	wire [31:0] a5,b5,c5,d5,e5;
	wire [31:0] a6,b6,c6,d6,e6;
	wire [31:0] a7,b7,c7,d7,e7;
	wire [31:0] a8,b8,c8,d8,e8;
	wire [31:0] a9,b9,c9,d9,e9;
	wire [31:0] a10,b10,c10,d10,e10;
	wire [31:0] a11,b11,c11,d11,e11;
	wire [31:0] a12,b12,c12,d12,e12;
	wire [31:0] a13,b13,c13,d13,e13;
	wire [31:0] a14,b14,c14,d14,e14;
	wire [31:0] a15,b15,c15,d15,e15;
	wire [31:0] a16,b16,c16,d16,e16;
	wire [31:0] a17,b17,c17,d17,e17;
	wire [31:0] a18,b18,c18,d18,e18;
	wire [31:0] a19,b19,c19,d19,e19;
	
	wire [31:0] a20,b20,c20,d20,e20;
	wire [31:0] a21,b21,c21,d21,e21;
	wire [31:0] a22,b22,c22,d22,e22;
	wire [31:0] a23,b23,c23,d23,e23;
	wire [31:0] a24,b24,c24,d24,e24;
	wire [31:0] a25,b25,c25,d25,e25;
	wire [31:0] a26,b26,c26,d26,e26;
	wire [31:0] a27,b27,c27,d27,e27;
	wire [31:0] a28,b28,c28,d28,e28;
	wire [31:0] a29,b29,c29,d29,e29;
	wire [31:0] a30,b30,c30,d30,e30;
	wire [31:0] a31,b31,c31,d31,e31;
	wire [31:0] a32,b32,c32,d32,e32;
	wire [31:0] a33,b33,c33,d33,e33;
	wire [31:0] a34,b34,c34,d34,e34;
	wire [31:0] a35,b35,c35,d35,e35;
	wire [31:0] a36,b36,c36,d36,e36;
	wire [31:0] a37,b37,c37,d37,e37;
	wire [31:0] a38,b38,c38,d38,e38;
	wire [31:0] a39,b39,c39,d39,e39;
	
	wire [31:0] a40,b40,c40,d40,e40;
	wire [31:0] a41,b41,c41,d41,e41;
	wire [31:0] a42,b42,c42,d42,e42;
	wire [31:0] a43,b43,c43,d43,e43;
	wire [31:0] a44,b44,c44,d44,e44;
	wire [31:0] a45,b45,c45,d45,e45;
	wire [31:0] a46,b46,c46,d46,e46;
	wire [31:0] a47,b47,c47,d47,e47;
	wire [31:0] a48,b48,c48,d48,e48;
	wire [31:0] a49,b49,c49,d49,e49;
	wire [31:0] a50,b50,c50,d50,e50;
	wire [31:0] a51,b51,c51,d51,e51;
	wire [31:0] a52,b52,c52,d52,e52;
	wire [31:0] a53,b53,c53,d53,e53;
	wire [31:0] a54,b54,c54,d54,e54;
	wire [31:0] a55,b55,c55,d55,e55;
	wire [31:0] a56,b56,c56,d56,e56;
	wire [31:0] a57,b57,c57,d57,e57;
	wire [31:0] a58,b58,c58,d58,e58;
	wire [31:0] a59,b59,c59,d59,e59;
	
	wire [31:0] a60,b60,c60,d60,e60;
	wire [31:0] a61,b61,c61,d61,e61;
	wire [31:0] a62,b62,c62,d62,e62;
	wire [31:0] a63,b63,c63,d63,e63;
	wire [31:0] a64,b64,c64,d64,e64;
	wire [31:0] a65,b65,c65,d65,e65;
	wire [31:0] a66,b66,c66,d66,e66;
	wire [31:0] a67,b67,c67,d67,e67;
	wire [31:0] a68,b68,c68,d68,e68;
	wire [31:0] a69,b69,c69,d69,e69;
	wire [31:0] a70,b70,c70,d70,e70;
	wire [31:0] a71,b71,c71,d71,e71;
	wire [31:0] a72,b72,c72,d72,e72;
	wire [31:0] a73,b73,c73,d73,e73;
	wire [31:0] a74,b74,c74,d74,e74;
	wire [31:0] a75,b75,c75,d75,e75;
	wire [31:0] a76,b76,c76,d76,e76;
	wire [31:0] a77,b77,c77,d77,e77;
	wire [31:0] a78,b78,c78,d78,e78;
	wire [31:0] a79,b79,c79,d79,e79;
	
	wire [31:0] aF,bF,cF,dF,eF;
	
	
	//Split 512-bit chunk into 16 32-bit words
	assign w0 = M0;
	assign w1 = M1;
	assign w2 = M2;
	assign w3 = M3;
	assign w4 = M4;
	assign w5 = M5;
	assign w6 = M6;
	assign w7 = M7;
	assign w8 = M8;
	assign w9 = M9;
	assign w10 = M10;
	assign w11 = M11;
	assign w12 = M12;
	assign w13 = M13;
	assign w14 = M14;
	assign w15 = M15;
	
	//Expand 16 32-bit words into 80 32-bit words
	w_expand expandWords16(.w1(w13), .w2(w8), .w3(w2), .w4(0), .wout(w16));
	w_expand expandWords17(.w1(w14), .w2(w9), .w3(w3), .w4(1), .wout(w17));
	w_expand expandWords18(.w1(w15), .w2(w10), .w3(w4), .w4(2), .wout(w18));
	w_expand expandWords19(.w1(w16), .w2(w11), .w3(w5), .w4(3), .wout(w19));
	w_expand expandWords20(.w1(w17), .w2(w12), .w3(w6), .w4(4), .wout(w20));
	w_expand expandWords21(.w1(w18), .w2(w13), .w3(w7), .w4(5), .wout(w21));
	w_expand expandWords22(.w1(w19), .w2(w14), .w3(w8), .w4(6), .wout(w22));
	w_expand expandWords23(.w1(w20), .w2(w15), .w3(w9), .w4(7), .wout(w23));
	w_expand expandWords24(.w1(w21), .w2(w16), .w3(w10), .w4(8), .wout(w24));
	w_expand expandWords25(.w1(w22), .w2(w17), .w3(w11), .w4(9), .wout(w25));
	w_expand expandWords26(.w1(w23), .w2(w18), .w3(w12), .w4(10), .wout(w26));
	w_expand expandWords27(.w1(w24), .w2(w19), .w3(w13), .w4(11), .wout(w27));
	w_expand expandWords28(.w1(w25), .w2(w20), .w3(w14), .w4(12), .wout(w28));
	w_expand expandWords29(.w1(w26), .w2(w21), .w3(w15), .w4(13), .wout(w29));
	w_expand expandWords30(.w1(w27), .w2(w22), .w3(w16), .w4(14), .wout(w30));
	w_expand expandWords31(.w1(w28), .w2(w23), .w3(w17), .w4(15), .wout(w31));
	w_expand expandWords32(.w1(w29), .w2(w24), .w3(w18), .w4(16), .wout(w32));
	w_expand expandWords33(.w1(w30), .w2(w25), .w3(w19), .w4(17), .wout(w33));
	w_expand expandWords34(.w1(w31), .w2(w26), .w3(w20), .w4(18), .wout(w34));
	w_expand expandWords35(.w1(w32), .w2(w27), .w3(w21), .w4(19), .wout(w35));
	w_expand expandWords36(.w1(w33), .w2(w28), .w3(w22), .w4(20), .wout(w36));
	w_expand expandWords37(.w1(w34), .w2(w29), .w3(w23), .w4(21), .wout(w37));
	w_expand expandWords38(.w1(w35), .w2(w30), .w3(w24), .w4(22), .wout(w38));
	w_expand expandWords39(.w1(w36), .w2(w31), .w3(w25), .w4(23), .wout(w39));
	w_expand expandWords40(.w1(w37), .w2(w32), .w3(w26), .w4(24), .wout(w40));
	w_expand expandWords41(.w1(w38), .w2(w33), .w3(w27), .w4(25), .wout(w41));
	w_expand expandWords42(.w1(w39), .w2(w34), .w3(w28), .w4(26), .wout(w42));
	w_expand expandWords43(.w1(w40), .w2(w35), .w3(w29), .w4(27), .wout(w43));
	w_expand expandWords44(.w1(w41), .w2(w36), .w3(w30), .w4(28), .wout(w44));
	w_expand expandWords45(.w1(w42), .w2(w37), .w3(w31), .w4(29), .wout(w45));
	w_expand expandWords46(.w1(w43), .w2(w38), .w3(w32), .w4(30), .wout(w46));
	w_expand expandWords47(.w1(w44), .w2(w39), .w3(w33), .w4(31), .wout(w47));
	w_expand expandWords48(.w1(w45), .w2(w40), .w3(w34), .w4(32), .wout(w48));
	w_expand expandWords49(.w1(w46), .w2(w41), .w3(w35), .w4(33), .wout(w49));
	w_expand expandWords50(.w1(w47), .w2(w42), .w3(w36), .w4(34), .wout(w50));
	w_expand expandWords51(.w1(w48), .w2(w43), .w3(w37), .w4(35), .wout(w51));
	w_expand expandWords52(.w1(w49), .w2(w44), .w3(w38), .w4(36), .wout(w52));
	w_expand expandWords53(.w1(w50), .w2(w45), .w3(w39), .w4(37), .wout(w53));
	w_expand expandWords54(.w1(w51), .w2(w46), .w3(w40), .w4(38), .wout(w54));
	w_expand expandWords55(.w1(w52), .w2(w47), .w3(w41), .w4(39), .wout(w55));
	w_expand expandWords56(.w1(w53), .w2(w48), .w3(w42), .w4(40), .wout(w56));
	w_expand expandWords57(.w1(w54), .w2(w49), .w3(w43), .w4(41), .wout(w57));
	w_expand expandWords58(.w1(w55), .w2(w50), .w3(w44), .w4(42), .wout(w58));
	w_expand expandWords59(.w1(w56), .w2(w51), .w3(w45), .w4(43), .wout(w59));
	w_expand expandWords60(.w1(w57), .w2(w52), .w3(w46), .w4(44), .wout(w60));
	w_expand expandWords61(.w1(w58), .w2(w53), .w3(w47), .w4(45), .wout(w61));
	w_expand expandWords62(.w1(w59), .w2(w54), .w3(w48), .w4(46), .wout(w62));
	w_expand expandWords63(.w1(w60), .w2(w55), .w3(w49), .w4(47), .wout(w63));
	w_expand expandWords64(.w1(w61), .w2(w56), .w3(w50), .w4(48), .wout(w64));
	w_expand expandWords65(.w1(w62), .w2(w57), .w3(w51), .w4(49), .wout(w65));
	w_expand expandWords66(.w1(w63), .w2(w58), .w3(w52), .w4(50), .wout(w66));
	w_expand expandWords67(.w1(w64), .w2(w59), .w3(w53), .w4(51), .wout(w67));
	w_expand expandWords68(.w1(w65), .w2(w60), .w3(w54), .w4(52), .wout(w68));
	w_expand expandWords69(.w1(w66), .w2(w61), .w3(w55), .w4(53), .wout(w69));
	w_expand expandWords70(.w1(w67), .w2(w62), .w3(w56), .w4(54), .wout(w70));
	w_expand expandWords71(.w1(w68), .w2(w63), .w3(w57), .w4(55), .wout(w71));
	w_expand expandWords72(.w1(w69), .w2(w64), .w3(w58), .w4(56), .wout(w72));
	w_expand expandWords73(.w1(w70), .w2(w65), .w3(w59), .w4(57), .wout(w73));
	w_expand expandWords74(.w1(w71), .w2(w66), .w3(w60), .w4(58), .wout(w74));
	w_expand expandWords75(.w1(w72), .w2(w67), .w3(w61), .w4(59), .wout(w75));
	w_expand expandWords76(.w1(w73), .w2(w68), .w3(w62), .w4(60), .wout(w76));
	w_expand expandWords77(.w1(w74), .w2(w69), .w3(w63), .w4(61), .wout(w77));
	w_expand expandWords78(.w1(w75), .w2(w70), .w3(w64), .w4(62), .wout(w78));
	w_expand expandWords79(.w1(w76), .w2(w71), .w3(w65), .w4(63), .wout(w79));
	
	//Round 1 (i = 0 through i = 19)
	round1 i0(h0, h1, h2, h3, h4, w0, k0, a1, b1, c1, d1, e1);
	round1 i1(a1, b1, c1, d1, e1, w1, k0, a2, b2, c2, d2, e2);
	round1 i2(a2, b2, c2, d2, e2, w2, k0, a3, b3, c3, d3, e3);
	round1 i3(a3, b3, c3, d3, e3, w3, k0, a4, b4, c4, d4, e4);
	round1 i4(a4, b4, c4, d4, e4, w4, k0, a5, b5, c5, d5, e5);
	round1 i5(a5, b5, c5, d5, e5, w5, k0, a6, b6, c6, d6, e6);
	round1 i6(a6, b6, c6, d6, e6, w6, k0, a7, b7, c7, d7, e7);
	round1 i7(a7, b7, c7, d7, e7, w7, k0, a8, b8, c8, d8, e8);
	round1 i8(a8, b8, c8, d8, e8, w8, k0, a9, b9, c9, d9, e9);
	round1 i9(a9, b9, c9, d9, e9, w9, k0, a10, b10, c10, d10, e10);
	round1 i10(a10, b10, c10, d10, e10, w10, k0, a11, b11, c11, d11, e11);
	round1 i11(a11, b11, c11, d11, e11, w11, k0, a12, b12, c12, d12, e12);
	round1 i12(a12, b12, c12, d12, e12, w12, k0, a13, b13, c13, d13, e13);
	round1 i13(a13, b13, c13, d13, e13, w13, k0, a14, b14, c14, d14, e14);
	round1 i14(a14, b14, c14, d14, e14, w14, k0, a15, b15, c15, d15, e15);
	round1 i15(a15, b15, c15, d15, e15, w15, k0, a16, b16, c16, d16, e16);
	round1 i16(a16, b16, c16, d16, e16, w16, k0, a17, b17, c17, d17, e17);
	round1 i17(a17, b17, c17, d17, e17, w17, k0, a18, b18, c18, d18, e18);
	round1 i18(a18, b18, c18, d18, e18, w18, k0, a19, b19, c19, d19, e19);
	round1 i19(a19, b19, c19, d19, e19, w19, k0, a20, b20, c20, d20, e20);
	
	//Round 2 (i = 20 through i = 39)
	round2 i20(a20, b20, c20, d20, e20, w20, k1, a21, b21, c21, d21, e21);
	round2 i21(a21, b21, c21, d21, e21, w21, k1, a22, b22, c22, d22, e22);
	round2 i22(a22, b22, c22, d22, e22, w22, k1, a23, b23, c23, d23, e23);
	round2 i23(a23, b23, c23, d23, e23, w23, k1, a24, b24, c24, d24, e24);
	round2 i24(a24, b24, c24, d24, e24, w24, k1, a25, b25, c25, d25, e25);
	round2 i25(a25, b25, c25, d25, e25, w25, k1, a26, b26, c26, d26, e26);
	round2 i26(a26, b26, c26, d26, e26, w26, k1, a27, b27, c27, d27, e27);
	round2 i27(a27, b27, c27, d27, e27, w27, k1, a28, b28, c28, d28, e28);
	round2 i28(a28, b28, c28, d28, e28, w28, k1, a29, b29, c29, d29, e29);
	round2 i29(a29, b29, c29, d29, e29, w29, k1, a30, b30, c30, d30, e30);
	round2 i30(a30, b30, c30, d30, e30, w30, k1, a31, b31, c31, d31, e31);
	round2 i31(a31, b31, c31, d31, e31, w31, k1, a32, b32, c32, d32, e32);
	round2 i32(a32, b32, c32, d32, e32, w32, k1, a33, b33, c33, d33, e33);
	round2 i33(a33, b33, c33, d33, e33, w33, k1, a34, b34, c34, d34, e34);
	round2 i34(a34, b34, c34, d34, e34, w34, k1, a35, b35, c35, d35, e35);
	round2 i35(a35, b35, c35, d35, e35, w35, k1, a36, b36, c36, d36, e36);
	round2 i36(a36, b36, c36, d36, e36, w36, k1, a37, b37, c37, d37, e37);
	round2 i37(a37, b37, c37, d37, e37, w37, k1, a38, b38, c38, d38, e38);
	round2 i38(a38, b38, c38, d38, e38, w38, k1, a39, b39, c39, d39, e39);
	round2 i39(a39, b39, c39, d39, e39, w39, k1, a40, b40, c40, d40, e40);

	//Round 3 (i = 40 through i = 59)
	round3 i40(a40, b40, c40, d40, e40, w40, k2, a41, b41, c41, d41, e41);
	round3 i41(a41, b41, c41, d41, e41, w41, k2, a42, b42, c42, d42, e42);
	round3 i42(a42, b42, c42, d42, e42, w42, k2, a43, b43, c43, d43, e43);
	round3 i43(a43, b43, c43, d43, e43, w43, k2, a44, b44, c44, d44, e44);
	round3 i44(a44, b44, c44, d44, e44, w44, k2, a45, b45, c45, d45, e45);
	round3 i45(a45, b45, c45, d45, e45, w45, k2, a46, b46, c46, d46, e46);
	round3 i46(a46, b46, c46, d46, e46, w46, k2, a47, b47, c47, d47, e47);
	round3 i47(a47, b47, c47, d47, e47, w47, k2, a48, b48, c48, d48, e48);
	round3 i48(a48, b48, c48, d48, e48, w48, k2, a49, b49, c49, d49, e49);
	round3 i49(a49, b49, c49, d49, e49, w49, k2, a50, b50, c50, d50, e50);
	round3 i50(a50, b50, c50, d50, e50, w50, k2, a51, b51, c51, d51, e51);
	round3 i51(a51, b51, c51, d51, e51, w51, k2, a52, b52, c52, d52, e52);
	round3 i52(a52, b52, c52, d52, e52, w52, k2, a53, b53, c53, d53, e53);
	round3 i53(a53, b53, c53, d53, e53, w53, k2, a54, b54, c54, d54, e54);
	round3 i54(a54, b54, c54, d54, e54, w54, k2, a55, b55, c55, d55, e55);
	round3 i55(a55, b55, c55, d55, e55, w55, k2, a56, b56, c56, d56, e56);
	round3 i56(a56, b56, c56, d56, e56, w56, k2, a57, b57, c57, d57, e57);
	round3 i57(a57, b57, c57, d57, e57, w57, k2, a58, b58, c58, d58, e58);
	round3 i58(a58, b58, c58, d58, e58, w58, k2, a59, b59, c59, d59, e59);
	round3 i59(a59, b59, c59, d59, e59, w59, k2, a60, b60, c60, d60, e60);

	//Round 4 (i = 60 through i = 79)
	round4 i60(a60, b60, c60, d60, e60, w60, k3, a61, b61, c61, d61, e61);
	round4 i61(a61, b61, c61, d61, e61, w61, k3, a62, b62, c62, d62, e62);
	round4 i62(a62, b62, c62, d62, e62, w62, k3, a63, b63, c63, d63, e63);
	round4 i63(a63, b63, c63, d63, e63, w63, k3, a64, b64, c64, d64, e64);
	round4 i64(a64, b64, c64, d64, e64, w64, k3, a65, b65, c65, d65, e65);
	round4 i65(a65, b65, c65, d65, e65, w65, k3, a66, b66, c66, d66, e66);
	round4 i66(a66, b66, c66, d66, e66, w66, k3, a67, b67, c67, d67, e67);
	round4 i67(a67, b67, c67, d67, e67, w67, k3, a68, b68, c68, d68, e68);
	round4 i68(a68, b68, c68, d68, e68, w68, k3, a69, b69, c69, d69, e69);
	round4 i69(a69, b69, c69, d69, e69, w69, k3, a70, b70, c70, d70, e70);
	round4 i70(a70, b70, c70, d70, e70, w70, k3, a71, b71, c71, d71, e71);
	round4 i71(a71, b71, c71, d71, e71, w71, k3, a72, b72, c72, d72, e72);
	round4 i72(a72, b72, c72, d72, e72, w72, k3, a73, b73, c73, d73, e73);
	round4 i73(a73, b73, c73, d73, e73, w73, k3, a74, b74, c74, d74, e74);
	round4 i74(a74, b74, c74, d74, e74, w74, k3, a75, b75, c75, d75, e75);
	round4 i75(a75, b75, c75, d75, e75, w75, k3, a76, b76, c76, d76, e76);
	round4 i76(a76, b76, c76, d76, e76, w76, k3, a77, b77, c77, d77, e77);
	round4 i77(a77, b77, c77, d77, e77, w77, k3, a78, b78, c78, d78, e78);
	round4 i78(a78, b78, c78, d78, e78, w78, k3, a79, b79, c79, d79, e79);
	round4 i79(a79, b79, c79, d79, e79, w79, k3, aF, bF, cF, dF, eF);
	
	//Calculate final hash
   // h0 = h0 + a
   // h1 = h1 + b 
   // h2 = h2 + c
   // h3 = h3 + d
   // h4 = h4 + e
	add_32 finalA(h0,aF,hash[159:128]);
	add_32 finalB(h1,bF,hash[127:96]);
	add_32 finalC(h2,cF,hash[95:64]);
	add_32 finalD(h3,dF,hash[63:32]);
	add_32 finalE(h4,eF,hash[31:0]);

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

module round1(a, b, c, d, e, w, k, aOut, bOut, cOut, dOut, eOut);
	input [31:0] a, b, c, d, e, w, k;
	output reg [31:0] aOut, bOut, cOut, dOut, eOut;
	
	wire [31:0] f, t1, t2, t3, t4, t5, temp, ctemp;
	
	f0 F0(b, c, d, f);
	
	//temp = (a leftrotate 5) + f + e + k + w[i] --> t1 + t3 + t2 --> temp = t1 + t4
	left_rotate5 rotate(a,t1);
	add_32 addkw(k,w,t2);
	add_32 addfe(f,e,t3);
	add_32 addt3t2(t3,t2,t4);
	add_32 addtemp(t1,t4,temp);
	
	left_rotate30 rotateC(b,ctemp);
	
	always@(a or b or c or d or e or w or k)		
	begin	
	
		eOut = d;
		dOut = c;
		cOut = ctemp;
		bOut = a;
		aOut = temp;
	
	end
	
endmodule

module round2(a, b, c, d, e, w, k, aOut, bOut, cOut, dOut, eOut);
	input [31:0] a, b, c, d, e, w, k;
	output reg [31:0] aOut, bOut, cOut, dOut, eOut;
	
	wire [31:0] f, t1, t2, t3, t4, t5, ctemp, temp;
	
	f1 F1(b, c, d, f);
	
	//temp = (a leftrotate 5) + f + e + k + w[i] --> t1 + t3 + t2 --> temp = t1 + t4
	left_rotate5 rotate(a,t1);
	add_32 addkw(k,w,t2);
	add_32 addfe(f,e,t3);
	add_32 addt3t2(t3,t2,t4);
	add_32 addtemp(t1,t4,temp);
	
	left_rotate30 rotateC(b,ctemp);
	
	always@(a or b or c or d or e or w or k)		
	begin	
	
		eOut = d;
		dOut = c;
		cOut = ctemp;
		bOut = a;
		aOut = temp;
	
	end
	
endmodule

module round3(a, b, c, d, e, w, k, aOut, bOut, cOut, dOut, eOut);
	input [31:0] a, b, c, d, e, w, k;
	output reg [31:0] aOut, bOut, cOut, dOut, eOut;
	
	wire [31:0] f, t1, t2, t3, t4, t5, ctemp, temp;
	
	f2 F2(b, c, d, f);
	
	//temp = (a leftrotate 5) + f + e + k + w[i] --> t1 + t3 + t2 --> temp = t1 + t4
	left_rotate5 rotate(a,t1);
	add_32 addkw(k,w,t2);
	add_32 addfe(f,e,t3);
	add_32 addt3t2(t3,t2,t4);
	add_32 addtemp(t1,t4,temp);
	
	left_rotate30 rotateC(b,ctemp);
	
	always@(a or b or c or d or e or w or k)		
	begin	
	
		eOut = d;
		dOut = c;
		cOut = ctemp;
		bOut = a;
		aOut = temp;
	
	end
	
endmodule

module round4(a, b, c, d, e, w, k, aOut, bOut, cOut, dOut, eOut);
	input [31:0] a, b, c, d, e, w, k;
	output reg [31:0] aOut, bOut, cOut, dOut, eOut;
	
	wire [31:0] f, t1, t2, t3, t4, t5, ctemp, temp;
	
	f3 F3(b, c, d, f);
	
	//temp = (a leftrotate 5) + f + e + k + w[i] --> t1 + t3 + t2 --> temp = t1 + t4
	left_rotate5 rotate(a,t1);
	add_32 addkw(k,w,t2);
	add_32 addfe(f,e,t3);
	add_32 addt3t2(t3,t2,t4);
	add_32 addtemp(t1,t4,temp);
	
	left_rotate30 rotateC(b,ctemp);
	
	always@(a or b or c or d or e or w or k)		
	begin	
	
		eOut = d;
		dOut = c;
		cOut = ctemp;
		bOut = a;
		aOut = temp;
	
	end
	
endmodule
