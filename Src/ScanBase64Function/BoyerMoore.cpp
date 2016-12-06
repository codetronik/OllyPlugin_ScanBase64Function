// Memory Search Algorithm
// Date: 2011. 12. 24 
// Usage: Search(PBYTE MemoryAddr, int MemorySize, int StartPosition, PBYTE Pattern, int PatternSize);
// Author : Codetronik 

#include <windows.h>
#include "BoyerMoore.h"

// A8 = Wild Char

bool CBoyerMoore::BuildBCT(unsigned char* Pattern, int PatternSize, int* BCT)
{
	int k=0;

	for (int i=0; i<256; i++)
		BCT[i] = -1;

	for (int j=0; j<PatternSize; j++ )
	{
		if(Pattern[j] == 0xA8)
			k++;
		
		BCT[Pattern[j]] = j;

	}

	if(k == 0)
		return false;
	else
		return true;
}

void CBoyerMoore::BuildGST(unsigned char* Pattern, int PatternSize, int* Suffix, int* GST)
{
    /*  Case 1 */
    int i = PatternSize;
    int j = PatternSize + 1;

    Suffix[i]=j; 
    
    while (i>0)
    {
        while (j<=PatternSize && Pattern[i-1] != Pattern[j-1])
        {
            if ( GST[j] == 0 ) 
                GST[j]=j-i;

            j=Suffix[j];
        }

        i--; 
        j--;
        
        Suffix[i] = j;
    }

    /*  Case 2 */
    j = Suffix[0];

    for ( i = 0; i <= PatternSize; i++ )
    {
        if ( GST[i] == 0 ) 
            GST[i] = j;

        if ( i == j ) 
            j = Suffix[j];
    }
}

int CBoyerMoore::Max( int A, int B )
{
    if ( A > B )
        return A;
    else
        return B;
}


int CBoyerMoore::Search(unsigned char* Text, int TextSize, int Start, unsigned char* Pattern, int PatternSize )
{
	unsigned char Temp;
	int nTemp = 0;
	int nMove=0;

	int BCT[256];
	int Suffix[512] = {0,};
	int GST[512] = {0,};

	int i = Start;
  
	int j = 0;
	bool bExist = false;
	int count  = 0;
    int Position = -1;

    bExist = BuildBCT( Pattern, PatternSize, BCT );
	BuildGST( Pattern, PatternSize, Suffix, GST );

    while (i <= TextSize - PatternSize)
    {

        j = PatternSize - 1;

        while (j >= 0 && ( Pattern[j] == Text[i+j] ) || Pattern[j] == 0xA8)   
		{
			count++;
			j--;			
		}
	
		if (j < 0)
        {
            Position = i;			
			break;            
        }

		count++;
				
		nMove = Max( GST[j+1], j-BCT[ Text[i+j] ] );
		
		if(nMove == PatternSize)
		{
			Temp = Text[i+j];
			Text[i+j] = 0xA8;
			nTemp = i;

			i+= Max( GST[j+1], j-BCT[ Text[i+j] ] );
		
			Text[nTemp+j] = Temp;
		}
		else
		{
			i+= nMove;
		}
	}

    return Position;
}
