#include <time.h>
#include <stdlib.h>
#include <stdio.h>

//char *attacks[] = {NULL, "Water", "Fire", "Wood", "Electricity"};
char* student_id = "0540015";

int boss_next_move(){
	int t = rand();
	return (t & 3) +1;
}

int anti_boss(int i){
	return i==1?4:i-1;
}

int main(){
	unsigned int seed;
	printf("%s\n", student_id);

	seed = time(0);
	srand(seed);

	int boss_move, player_move;
	for (int i=0;i<1000;i++){
		boss_move = boss_next_move();
		player_move = anti_boss(boss_move);
		printf("%d\n", player_move);
	}
}