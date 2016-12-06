#ifndef __BOYERMOORE_H__
#define __BOYERMOORE_H__

class CBoyerMoore
{
public:
	int Search(unsigned char* Text, int TextSize, int Start, unsigned char* Pattern, int PatternSize);
private:
	bool BuildBCT(unsigned char* Pattern, int PatternSize, int* BCT);
	void BuildGST(unsigned char* Pattern, int PatternSize, int* Suffix, int* GST);
	int Max(int A, int B);
	
};

#endif