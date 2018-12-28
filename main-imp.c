/*
 * Autor David Dejmal xdejma00
 * Projekt IMP 2018
 * Budik pro sedmisegmentovy display
 */
/*
*Cast	pin
*A		8
*B		12
*C		4
*D		2
*E		1
*F		9
*G		5
*DP		3
*
* cislice	segmenty	piny
*	0	ABCDEF		8,12,4,2,1
*	1	BC			12,4
*	2	ABGED		8,12,5,1,2
*	3	ABGCD		8,12,5,4,2
*	4	FGBC		9,5,12,4
*	5	AFGCD		8,9,5,4,2
*	6	AFGEDC		8,9,5,1,2,4
*	7	ABC			8,12,4
*	8	ABCDEFG		8,12,4,2,1,9,5
*	9	ABCDFG		8,12,4,2,9,5
*/
#include "MK60D10.h"
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#define BTN_PRAVO 0x400 // Port E, bit 10
#define BTN_DOLE 0x1000 // Port E, bit 12
#define BTN_LEVO 0x8000000 // Port E, bit 27
#define BTN_HORE 0x4000000 // Port E, bit 26
#define BTN_CENT 0x800 // Port E, bit 11


			//‭0b00DCEX4G0000000000002AB13F000000
#define SEG_0 0b00000101000000000000000000000000
#define SEG_1 0b00101101000000000000010001000000
#define SEG_2 0b00010100000000000000000001000000
#define SEG_3 0b00001100000000000000000001000000
#define SEG_4 0b00101100000000000000010000000000
#define SEG_5 0b00001100000000000000001000000000
#define SEG_6 0b00000100000000000000001000000000
#define SEG_7 0b00101101000000000000000001000000
#define SEG_8 0b00000100000000000000000000000000
#define SEG_9 0b00001100000000000000000000000000

#define DOTT 0b00000100000000000000000000000000

#define NO_0 0b00000000000000000000000100000000
#define NO_1 0b00000000000000000000100000000000
#define NO_2 0b00000000000000000000000010000000
#define NO_3 0b00000010000000000000000000000000


/* 0- hodiny	- n
 * 1- nasvaeni casu - nc
 * 2- cas buzeni - cb
*/
int stav = 0;

/*
 * 0 - budik off
 * 1- budik on
 */
bool budik = false;

/*
 * promena cekani mezi pridanim hodnoty
 */
int wait = 150;
int now = 0;

int cas[]={0,0,0,0};
int wake_time[]={0,0,0,5};

bool mod = false;

/*
 * vraci PTA->PDOR = GPIO_PDOR_PDO(x)
 */
int make_mask(int pozice)
{
	int help;
	if(stav==2)
	{
		switch (wake_time[pozice]) {
			case 0:
				help=SEG_0;
				break;
			case 1:
				help=SEG_1;
				break;
			case 2:
				help=SEG_2;
				break;
			case 3:
				help=SEG_3;
				break;
			case 4:
				help=SEG_4;
				break;
			case 5:
				help=SEG_5;
				break;
			case 6:
				help=SEG_6;
				break;
			case 7:
				help=SEG_7;
				break;
			case 8:
				help=SEG_8;
				break;
			case 9:
				help=SEG_9;
				break;
			default:
				help=SEG_9;
				break;
		}
	}
	else
	{
		switch (cas[pozice]) {
			case 0:
				help=SEG_0;
				break;
			case 1:
				help=SEG_1;
				break;
			case 2:
				help=SEG_2;
				break;
			case 3:
				help=SEG_3;
				break;
			case 4:
				help=SEG_4;
				break;
			case 5:
				help=SEG_5;
				break;
			case 6:
				help=SEG_6;
				break;
			case 7:
				help=SEG_7;
				break;
			case 8:
				help=SEG_8;
				break;
			case 9:
				help=SEG_9;
				break;
			default:
				help=SEG_9;
				break;
		}
	}
	switch (pozice) {
		case 0:
			help=help+NO_0;
			break;
		case 1:
			help=help+NO_1;
			break;
		case 2:
			help=help+NO_2;
			break;
		case 3:
			help=help+NO_3;
			break;
		default:
			help=help+NO_0+NO_1+NO_2+NO_3;
			break;
	}
	if(budik==true)
	{
		help=help-DOTT;
	}
	return help;
}

void add_ms()
{
	if(stav==2)
	{
		if(mod==false)
		{
			if(wake_time[3]<=8)
			{
				wake_time[3]++;
			}
			else	//***9
			{
				wake_time[3]=0;
				if(wake_time[2]<=4)
				{
					wake_time[2]++;
				}
				else	//**59
				{
					wake_time[2]=0;
				}
			}
		}
		else
		{
			if(wake_time[1]<=8)
			{
				wake_time[1]++;
			}
			else	//***9
			{
				wake_time[1]=0;
				if(wake_time[0]<=4)
				{
					wake_time[0]++;
				}
				else	//**59
				{
					wake_time[0]=0;
				}
			}
		}

	}
	else
	{
		if(mod==false)
		{
			if(cas[3]<=8)
			{
				cas[3]++;
			}
			else	//***9
			{
				cas[3]=0;
				if(cas[2]<=4)
				{
					cas[2]++;
				}
				else	//**59
				{
					cas[2]=0;
				}
			}
		}
		else
		{
			if(cas[1]<=8)
			{
				cas[1]++;
			}
			else	//***9
			{
				cas[1]=0;
				if(cas[0]<=4)
				{
					cas[0]++;
				}
				else	//**59
				{
					cas[0]=0;
				}
			}
		}
	}
}

void add_one()
{
	if(stav==2)
	{
		if(wake_time[3]<=8)
		{
			wake_time[3]++;
		}
		else	//***9
		{
			wake_time[3]=0;
			if(wake_time[2]<=4)
			{
				wake_time[2]++;
			}
			else	//**59
			{
				wake_time[2]=0;
				if(wake_time[1]<=8)
				{
					wake_time[1]++;
				}
				else	//*959
				{
					wake_time[1]=0;
					if(wake_time[0]<=4)
					{
						wake_time[0]++;
					}
					else	//5959
					{
						wake_time[0]=0;

					}
				}
			}
		}
	}
	else
	{
		if(cas[3]<=8)
		{
			cas[3]++;
		}
		else	//***9
		{
			cas[3]=0;
			if(cas[2]<=4)
			{
				cas[2]++;
			}
			else	//**59
			{
				cas[2]=0;
				if(cas[1]<=8)
				{
					cas[1]++;
				}
				else	//*959
				{
					cas[1]=0;
					if(cas[0]<=4)
					{
						cas[0]++;
					}
					else	//5959
					{
						cas[0]=0;
					}
				}
			}
		}
	}

}

// cekani systemove - pro bzucak
void delay(unsigned long long int bound) {
    for(unsigned long long int i=0; i<bound; i++);
}

// INIT
void Init() {
	//MCU init
    MCG_C4 |= ( MCG_C4_DMX32_MASK | MCG_C4_DRST_DRS(0x01) );	//zakladni nastaveni hodin
    SIM_CLKDIV1 |= SIM_CLKDIV1_OUTDIV1(0x00);
    WDOG_STCTRLH &= ~WDOG_STCTRLH_WDOGEN_MASK; // turn off watchdog

    // Enable CLOCK
	 SIM->SCGC5 = SIM_SCGC5_PORTA_MASK | SIM_SCGC5_PORTB_MASK | SIM_SCGC5_PORTE_MASK| SIM_SCGC5_LPTIMER_MASK;
    //casvac

    LPTMR0_CSR &= ~LPTMR_CSR_TEN_MASK;     // Turn OFF LPTMR to perform setup

    LPTMR0_PSR = ( LPTMR_PSR_PRESCALE(0) // 0000 is div 2
                 | LPTMR_PSR_PBYP_MASK  // LPO feeds directly to LPT
                 | LPTMR_PSR_PCS(1)) ; // use the choice of clock

    LPTMR0_CMR = 0x400;  // Set compare value

    LPTMR0_CSR =(  LPTMR_CSR_TCF_MASK   // Clear any pending interrupt (now)
                 | LPTMR_CSR_TIE_MASK   // LPT interrupt enabled
                );

    NVIC_EnableIRQ(LPTMR0_IRQn);

    LPTMR0_CSR |= LPTMR_CSR_TEN_MASK;   // Turn ON LPTMR0 and start counting


    /* Set corresponding PTB pins (connected to LED's) for GPIO functionality */
    PORTB->PCR[5] = PORT_PCR_MUX(0x01); // D9
    PORTB->PCR[4] = PORT_PCR_MUX(0x01); // D10
    PORTB->PCR[3] = PORT_PCR_MUX(0x01); // D11
    PORTB->PCR[2] = PORT_PCR_MUX(0x01); // D12


			PORTE->PCR[10] = ( PORT_PCR_ISF(0x01) // Nuluj ISF (Interrupt Status Flag)
					| PORT_PCR_IRQC(0x0A) // Interrupt enable on failing edge
					| PORT_PCR_MUX(0x01) // Pin Mux Control to GPIO
					| PORT_PCR_PE(0x01) // Pull resistor enable...
					| PORT_PCR_PS(0x01)); // ...select Pull-Up

			PORTE->PCR[12] = ( PORT_PCR_ISF(0x01) // Nuluj ISF (Interrupt Status Flag)
					| PORT_PCR_IRQC(0x0A) // Interrupt enable on failing edge
					| PORT_PCR_MUX(0x01) // Pin Mux Control to GPIO
					| PORT_PCR_PE(0x01) // Pull resistor enable...
					| PORT_PCR_PS(0x01)); // ...select Pull-Up

			PORTE->PCR[27] = ( PORT_PCR_ISF(0x01) // Nuluj ISF (Interrupt Status Flag)
					| PORT_PCR_IRQC(0x0A) // Interrupt enable on failing edge
					| PORT_PCR_MUX(0x01) // Pin Mux Control to GPIO
					| PORT_PCR_PE(0x01) // Pull resistor enable...
					| PORT_PCR_PS(0x01)); // ...select Pull-Up

			PORTE->PCR[26] = ( PORT_PCR_ISF(0x01) // Nuluj ISF (Interrupt Status Flag)
					| PORT_PCR_IRQC(0x0A) // Interrupt enable on failing edge
					| PORT_PCR_MUX(0x01) // Pin Mux Control to GPIO
					| PORT_PCR_PE(0x01) // Pull resistor enable...
					| PORT_PCR_PS(0x01)); // ...select Pull-Up

			PORTE->PCR[11] = ( PORT_PCR_ISF(0x01) // Nuluj ISF (Interrupt Status Flag)
					| PORT_PCR_IRQC(0x0A) // Interrupt enable on failing edge
					| PORT_PCR_MUX(0x01) // Pin Mux Control to GPIO
					| PORT_PCR_PE(0x01) // Pull resistor enable...
					| PORT_PCR_PS(0x01)); // ...select Pull-Up
	    // Pozn.: Pull-Up rezistory je NUTNE zapnout, protoze jsou tlacitka pripojena
	    // z portu primo na zem (stisk da na portu log. 0, tj. generuje SESTUPNOU hranu),
	    // Pull-Up rezistor zajisti, ze nestisknute tlacitko da na portu STABILNI "1".
	    // Stiskem tlacitka pak generujeme preruseni, ktere musi byt nakonfigurovano
	    // prave na SESTUPNOU hranu na prislusnych vyvodech portu B. Vizte schema kitu.

		    // PORT A
			 PORTA->PCR[4] = PORT_PCR_MUX(0x01);

		   	PORTA->PCR[6] = PORT_PCR_MUX(0x01);
		   	PORTA->PCR[7] = PORT_PCR_MUX(0x01);
		   	PORTA->PCR[8] = PORT_PCR_MUX(0x01);
		   	PORTA->PCR[9] = PORT_PCR_MUX(0x01);
		   	PORTA->PCR[10] = PORT_PCR_MUX(0x01);
		   	PORTA->PCR[11] = PORT_PCR_MUX(0x01);

		   	PORTA->PCR[24] = PORT_PCR_MUX(0x01);
		   	PORTA->PCR[25] = PORT_PCR_MUX(0x01);
		   	PORTA->PCR[26] = PORT_PCR_MUX(0x01);
		   	PORTA->PCR[27] = PORT_PCR_MUX(0x01);
		   	PORTA->PCR[28] = PORT_PCR_MUX(0x01);
		   	PORTA->PCR[29] = PORT_PCR_MUX(0x01);

		    // set a port as output
		   	//0b00111111000000000000111111010000
		    PTA->PDDR = GPIO_PDDR_PDD(0b00111111000000000000111111010000);
		    //‭0b00DCEX4G0000000000002AB13F000000‬
		    PTA->PDOR = GPIO_PDOR_PDO(0b00001110000000000000100110000000);

		    /* Change corresponding PTB port pins as outputs */
		    PTB->PDDR = GPIO_PDDR_PDD( 0x3C );
		    PTB->PDOR |= GPIO_PDOR_PDO( 0x3C); // turn all LEDs OFF

	NVIC_ClearPendingIRQ(PORTE_IRQn); // Nuluj priznak preruseni od portu B
	NVIC_EnableIRQ(PORTE_IRQn);       // Povol preruseni od portu E
}

// ALARM ALARM!!!
void alarm()
{
    for (unsigned int q=0; q<200; q++) {
        PTA->PDOR = GPIO_PDOR_PDO(0x0010);
        PTB->PDOR &= ~GPIO_PDOR_PDO(0x3C);
		for(int i=0;i<4;i++)
		{
			PTA->PDOR = GPIO_PDOR_PDO(make_mask(i));
			delay(100);
		}
        PTA->PDOR = GPIO_PDOR_PDO(0x0000);
        PTB->PDOR |= GPIO_PDOR_PDO(0x3C);
        delay(500);
    }
}


void PORTE_IRQHandler(void) {

	//alarm();
	delay(3000);

	//printf("TLACITKO!!!\n");

    if(PORTE->ISFR & BTN_DOLE)
    {
    	if(!(GPIOE->PDIR & BTN_DOLE))
    	{
    		if(stav==0)
    		{
    			stav=2;
        		alarm();
        		printf("budik setting!!\n");
    		}
    		else if(stav==2)
    		{
    			stav=0;
        		alarm();
        		printf("end budik setting!!\n");
        		mod=false;
    		}
    	}
    }
    //nastaveni casu
    else if(PORTE->ISFR & BTN_HORE)
    {
    	if(!(GPIOE->PDIR & BTN_HORE))
    	{

    		if(stav==0)
    		{
    			stav=1;
        		alarm();
        		printf("cas setting!!!\n");
    		}
    		else if(stav==1)
    		{
    			stav=0;
        		alarm();
        		printf("end cas setting!!\n");
        		mod=false;
    		}
    	}
    }
    else if(PORTE->ISFR & BTN_LEVO)
    {
    	if(!(GPIOE->PDIR & BTN_LEVO)&&stav!=0)
    	{
    		alarm();
    		printf("BTN_LEVO!!!\n");
    	}
    }

    else if(PORTE->ISFR & BTN_PRAVO)
    {
    	while(!(GPIOE->PDIR & BTN_PRAVO)&&stav!=0)
    	{
    		//zapnuti/vypnuti budiku
    		if(stav==1)
    		{
    			//printf("+ nastaveni cas!!!\n");
    			add_ms();
    		}
    		// nastaveni casu
    		else if(stav==2)
    		{
    			//printf("+ budik cas!!!\n");
    			add_ms();
    		}
    		while (now<wait) {
    			if((GPIOE->PDIR & BTN_PRAVO))
    			{
    				break;
    			}
				//vypis
				for(int i=0;i<4;i++)
				{
					PTA->PDOR = GPIO_PDOR_PDO(make_mask(i));
					delay(800);
				}
				now++;
    		}
    		now=0;
			if(wait>20)
			{
				wait=wait-5;
			}
    	}
    	wait=150;
    }

    else if(PORTE->ISFR & BTN_CENT)
    {
    	if(!(GPIOE->PDIR & BTN_CENT))
    	{
    		//alarm();
    		//printf("BTN_CENT!!!\n");
    		//zapnuti/vypnuti budiku
    		if(stav==0)
    		{
        		budik=!budik;
    		}
    		// nastaveni casu
    		else if(stav==1)
    		{
    			alarm();
    			//printf("m/s cas!!!\n");
    			mod=!mod;
    		}
    		// nastaveni budiku
    		else if(stav==2)
    		{
    			alarm();
    			//printf("m/s budik!!!\n");
    			mod=!mod;
    		}

    	}
    }

    PORTE->ISFR=~0;	//nuluje interupt
}


void LPTMR0_IRQHandler(void){
	if(stav==2)
	{
		stav=0;
	    add_one();
	    stav=2;
	}
	else if(stav==0)
	{
		add_one();
	}
    if((memcmp(cas, wake_time, sizeof(cas)) == 0)&& budik==true && stav==0)	//cas budiku
    {
    	for(int i=0;i<4;i++)
    	{
        	alarm();
        	delay(500);
    	}
    }
    LPTMR0_CMR = 0x400; // !! the CMR reg. may only be changed while TCF == 1
    LPTMR0_CSR |=  LPTMR_CSR_TCF_MASK; // writing 1 to TCF tclear the flag
}

int main(void)
{

	Init();

    /* This for loop should be replaced. By default this loop allows a single stepping. */
    while (1) {
    	for(int i=0;i<4;i++)
    	{
    		PTA->PDOR = GPIO_PDOR_PDO(make_mask(i));
		    delay(800);
		}

    }
    /* Never leave main */
    return 0;
}
////////////////////////////////////////////////////////////////////////////////
// EOF
////////////////////////////////////////////////////////////////////////////////
